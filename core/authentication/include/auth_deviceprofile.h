/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permission and
 * limitations under the License.
 */

#ifndef AUTH_DEVICEPROFILE_H
#define AUTH_DEVICEPROFILE_H

#include <stdint.h>

#include "auth_session_key.h"
#include "auth_uk_manager.h"
#include "auth_user_common_key.h"
#include "lnn_node_info.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef enum {
    UPDATE_ACL_SUCC = 0,
    UPDATE_ACL_NOT_MATCH,
    GET_ALL_ACL_FAIL,
    GET_ALL_ACL_IS_EMPTY,
    MATCH_ONE_ACL,
} UpdateDpAclResult;

typedef struct {
    char udid[UDID_BUF_LEN];
    int32_t userId;
} TrustedInfo;

typedef struct {
    int64_t accountId;
    const char *deviceId;
    int32_t peerUserId;
} UpdateDpAclParams;

bool IsPotentialTrustedDeviceDp(const char *deviceIdHash, bool isOnlyPointToPoint);
bool DpHasAccessControlProfile(const char *udid, bool isNeedUserId, int32_t localUserId);
void UpdateDpSameAccount(UpdateDpAclParams *aclParams, SessionKey sessionKey, bool isNeedUpdateDk,
    AclWriteState aclState);
void UpdateDpSameAccountWithoutUserKey(UpdateDpAclParams *aclParams, AclWriteState aclState);
void DelNotTrustDevice(const char *udid);
void DelSessionKeyProfile(int32_t sessionKeyId);
bool GetSessionKeyProfile(int32_t sessionKeyId, uint8_t *sessionKey, uint32_t *length);
int32_t GetAccessUkIdSameAccount(const AuthACLInfo *acl, int32_t *ukId, uint64_t *time);
int32_t GetAccessUkIdDiffAccountWithUserLevel(const AuthACLInfo *acl, int32_t *ukId, uint64_t *time);
int32_t GetAccessUkIdDiffAccount(const AuthACLInfo *acl, int32_t *ukId, uint64_t *time);
int32_t GetAccessUkByUkId(int32_t sessionKeyId, uint8_t *uk, uint32_t ukLen);
void UpdateAssetSessionKeyByAcl(
    AuthACLInfo *info, const uint8_t *sessionKey, uint32_t sessionKeyLen, int32_t *sessionKeyId, bool isSameAccount);
bool IsSKIdInvalid(int32_t sessionKeyId, const char *accountHash, const char *udidShortHash, int32_t userId);
int32_t SelectAllAcl(TrustedInfo **trustedInfoArray, uint32_t *num);
bool IsTrustedDeviceFromAccess(const char *peerAccountHash, const char *peerUdid, int32_t peerUserId);
bool IsExistUkInAclProfile(const char *localUdid, const char *peerUdid);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_DEVICEPROFILE_H */

