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

#include "auth_device.h"
#include "auth_interface.h"
#include "auth_manager_struct.h"
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

int32_t AuthManagerSetSessionKey(int64_t authSeq, AuthSessionInfo *info, const SessionKey *sessionKey,
    bool isConnect, bool isOldKey);
int32_t AuthManagerGetSessionKey(int64_t authSeq, const AuthSessionInfo *info, SessionKey *sessionKey);

void AuthManagerSetAuthPassed(int64_t authSeq, const AuthSessionInfo *info);
void AuthManagerSetAuthFailed(int64_t authSeq, const AuthSessionInfo *info, int32_t reason);
void AuthManagerSetAuthFinished(int64_t authSeq, const AuthSessionInfo *info);
bool IsNeedAuthLimit(const char *udidHash);
void ClearAuthLimitMap(void);

void AuthNotifyAuthPassed(int64_t authSeq, const AuthSessionInfo *info);

/* Note: must call DelAuthManager to free. */
AuthManager *GetAuthManagerByAuthId(int64_t authId);
AuthManager *GetAuthManagerByConnInfo(const AuthConnInfo *connInfo, bool isServer);
void RemoveAuthSessionKeyByIndex(int64_t authId, int32_t index, AuthLinkType type);
void DelAuthManager(AuthManager *auth, int32_t type);
void DelDupAuthManager(AuthManager *auth);
void RemoveAuthManagerByAuthId(AuthHandle authHandle);
int32_t AuthDeviceGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo);
int32_t AuthDeviceGetPreferConnInfoWithoutSle(const char *uuid, AuthConnInfo *connInfo);
int32_t AuthDeviceGetConnInfoByType(const char *uuid, AuthLinkType type, AuthConnInfo *connInfo);
int32_t AuthDeviceGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo);
int32_t AuthDeviceGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo);
/*check whether AUTH device is exist or not*/
bool AuthDeviceCheckConnInfo(const char* uuid, AuthLinkType type, bool checkConnection);
int32_t AuthDeviceGetUsbConnInfo(const char *uuid, AuthConnInfo *connInfo);

/* for ProxyChannel & P2P TcpDirectchannel */
void AuthDeviceGetLatestIdByUuid(const char *uuid, AuthLinkType type, AuthHandle *authHandle);
int64_t AuthDeviceGetIdByConnInfo(const AuthConnInfo *connInfo, bool isServer);
int64_t AuthDeviceGetIdByUuid(const char *uuid, AuthLinkType type, bool isServer);
int32_t AuthDeviceGetAuthHandleByIndex(const char *udid, bool isServer, int32_t index, AuthHandle *authHandle);
AuthManager *NewAuthManager(int64_t authSeq, const AuthSessionInfo *info);
int32_t AuthDeviceSetP2pMac(int64_t authId, const char *p2pMac);

int32_t AuthDeviceInit(const AuthTransCallback *callback);
int32_t RegTrustListenerOnHichainSaStart(void);
int32_t GetHmlOrP2pAuthHandle(AuthHandle **authHandle, int32_t *num);
void AuthDeviceDeinit(void);
int64_t GetActiveAuthIdByConnInfo(const AuthConnInfo *connInfo, bool judgeTimeOut);
int64_t GetLatestIdByConnInfo(const AuthConnInfo *connInfo);
int32_t GetAuthConnInfoByUuid(const char *uuid, AuthLinkType type, AuthConnInfo *connInfo);
int32_t GetConnectionIdByHandle(AuthHandle handle);
int32_t TryGetBrConnInfo(const char *uuid, AuthConnInfo *connInfo);
void RemoveNotPassedAuthManagerByUdid(const char *udid);
AuthManager *GetDeviceAuthManager(int64_t authSeq, const AuthSessionInfo *info, bool *isNewCreated,
    int64_t lastAuthSeq);
bool IsHaveAuthIdByConnId(uint64_t connId);
void DelAuthManagerByConnectionId(uint32_t connectionId);
bool RawLinkNeedUpdateAuthManager(const char *uuid, bool isServer);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_MANAGER_H */
