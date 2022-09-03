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
#include "auth_session_fsm.h"
#include "auth_session_key.h"
#include "common_list.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    int64_t authId;
    bool isServer;
    /* 连接信息 */
    uint64_t connId;
    AuthConnInfo connInfo;
    uint64_t lastActiveTime;
    /* 密钥信息 */
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

int32_t AuthManagerSetSessionKey(int64_t authSeq, const AuthSessionInfo *info, const SessionKey *sessionKey);
int32_t AuthManagerGetSessionKey(int64_t authSeq, const AuthSessionInfo *info, SessionKey *sessionKey);

void AuthManagerSetAuthPassed(int64_t authSeq, const AuthSessionInfo *info);
void AuthManagerSetAuthFailed(int64_t authSeq, const AuthSessionInfo *info, int32_t reason);

/* Note: must call DelAuthManager to free. */
AuthManager *GetAuthManagerByAuthId(int64_t authId);
void DelAuthManager(AuthManager *auth, bool removeAuthFromList);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_MANAGER_H */
