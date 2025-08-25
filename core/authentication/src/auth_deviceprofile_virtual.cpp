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

#include "auth_deviceprofile.h"

bool IsPotentialTrustedDeviceDp(const char *deviceIdHash, bool isOnlyPointToPoint)
{
    (void)deviceIdHash;
    (void)isOnlyPointToPoint;
    return true;
}

bool DpHasAccessControlProfile(const char *udid, bool isNeedUserId, int32_t localUserId)
{
    (void)udid;
    (void)isNeedUserId;
    (void)localUserId;
    return false;
}

void UpdateDpSameAccount(UpdateDpAclParams *aclParams, SessionKey sessionKey, bool isNeedUpdateDk,
    AclWriteState aclState)
{
    (void)aclParams;
    (void)sessionKey;
    (void)isNeedUpdateDk;
    (void)aclState;
}

void UpdateDpSameAccountWithoutUserKey(UpdateDpAclParams *aclParams, AclWriteState aclState)
{
    (void)aclParams;
    (void)aclState;
}

void DelNotTrustDevice(const char *udid)
{
    (void)udid;
}

void DelSessionKeyProfile(int32_t sessionKeyId)
{
    (void)sessionKeyId;
}

bool GetSessionKeyProfile(int32_t sessionKeyId, uint8_t *sessionKey, uint32_t *length)
{
    (void)sessionKeyId;
    (void)sessionKey;
    (void)length;
    return false;
}

int32_t GetAccessUkIdSameAccount(const AuthACLInfo *acl, int32_t *ukId, uint64_t *time)
{
    (void)acl;
    (void)ukId;
    (void)time;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t GetAccessUkIdDiffAccountWithUserLevel(const AuthACLInfo *acl, int32_t *ukId, uint64_t *time)
{
    (void)acl;
    (void)ukId;
    (void)time;
    return SOFTBUS_AUTH_ACL_NOT_FOUND;
}

int32_t GetAccessUkIdDiffAccount(const AuthACLInfo *acl, int32_t *ukId, uint64_t *time)
{
    (void)acl;
    (void)ukId;
    (void)time;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t GetAccessUkByUkId(int32_t sessionKeyId, uint8_t *uk, uint32_t ukLen)
{
    (void)sessionKeyId;
    (void)uk;
    (void)ukLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

void UpdateAssetSessionKeyByAcl(
    AuthACLInfo *info, const uint8_t *sessionKey, uint32_t sessionKeyLen, int32_t *sessionKeyId, bool isSameAccount)
{
    (void)info;
    (void)sessionKey;
    (void)sessionKeyLen;
    (void)sessionKeyId;
    (void)isSameAccount;
}

bool IsSKIdInvalid(int32_t sessionKeyId, const char *accountHash, const char *udidShortHash, int32_t userId)
{
    (void)sessionKeyId;
    (void)accountHash;
    (void)udidShortHash;
    (void)userId;
    return false;
}

int32_t SelectAllAcl(TrustedInfo **trustedInfoArray, uint32_t *num)
{
    (void)trustedInfoArray;
    (void)num;
    return SOFTBUS_NOT_IMPLEMENT;
}

bool IsTrustedDeviceFromAccess(const char *peerAccountHash, const char *peerUdid, int32_t peerUserId)
{
    (void)peerAccountHash;
    (void)peerUdid;
    (void)peerUserId;
    return false;
}