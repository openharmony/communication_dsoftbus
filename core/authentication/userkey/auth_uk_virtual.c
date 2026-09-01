/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "auth_uk_manager.h"
#include "auth_user_common_key.h"

#include "auth_log.h"
#include "softbus_error_code.h"

int32_t AuthFindUkIdByAclInfo(const AuthACLInfo *acl, int32_t *ukId)
{
    (void)acl;
    (void)ukId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthGenUkIdByAclInfo(const AuthACLInfo *acl, uint32_t requestId, const AuthGenUkCallback *genCb)
{
    (void)acl;
    (void)requestId;
    (void)genCb;
    return SOFTBUS_NOT_IMPLEMENT;
}

uint32_t AuthGetUkDecryptSize(uint32_t inLen)
{
    (void)inLen;
    return 0;
}

int32_t AuthEncryptByUkId(int32_t ukId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    (void)ukId;
    (void)inData;
    (void)inLen;
    (void)outData;
    (void)outLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t AuthDecryptByUkId(int32_t ukId, const uint8_t *inData, uint32_t inLen, uint8_t *outData, uint32_t *outLen)
{
    (void)ukId;
    (void)inData;
    (void)inLen;
    (void)outData;
    (void)outLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

uint32_t GenUkSeq(void)
{
    return 0;
}

bool CompareByAllAcl(const AuthACLInfo *oldAcl, const AuthACLInfo *newAcl, bool isSameSide)
{
    (void)oldAcl;
    (void)newAcl;
    (void)isSameSide;
    return false;
}

bool CompareByAclDiffAccount(const AuthACLInfo *oldAcl, const AuthACLInfo *newAcl, bool isSameSide)
{
    (void)oldAcl;
    (void)newAcl;
    (void)isSameSide;
    return false;
}

bool CompareByAclDiffAccountWithUserLevel(const AuthACLInfo *oldAcl, const AuthACLInfo *newAcl, bool isSameSide)
{
    (void)oldAcl;
    (void)newAcl;
    (void)isSameSide;
    return false;
}

bool CompareByAclSameAccount(const AuthACLInfo *oldAcl, const AuthACLInfo *newAcl, bool isSameSide)
{
    (void)oldAcl;
    (void)newAcl;
    (void)isSameSide;
    return false;
}

bool AuthIsUkExpired(uint64_t time)
{
    (void)time;
    return true;
}

int32_t UkNegotiateInit(void)
{
    return SOFTBUS_OK;
}

void UkNegotiateDeinit(void)
{
}

void UkNegotiateSessionInit(void)
{
}

void PrintfAuthAclInfo(uint32_t requestId, uint32_t channelId, const AuthACLInfo *info)
{
    (void)requestId;
    (void)channelId;
    (void)info;
}

bool IsNeedSinkGenerateUk(const char *peerNetworkId)
{
    (void)peerNetworkId;
    return false;
}

int32_t AuthUserKeyInit(void)
{
    return SOFTBUS_OK;
}

void DeinitUserKeyList(void)
{
}

int32_t AuthInsertUserKey(
    const AuthACLInfo *aclInfo, const AuthUserKeyInfo *userKeyInfo, bool isUserBindLevel, DpBindType type)
{
    (void)aclInfo;
    (void)userKeyInfo;
    (void)isUserBindLevel;
    (void)type;
    return SOFTBUS_NOT_IMPLEMENT;
}

void DelUserKeyByNetworkId(const char *networkId)
{
    (void)networkId;
}

int32_t GetUserKeyInfoSameAccount(const AuthACLInfo *aclInfo, AuthUserKeyInfo *userKeyInfo)
{
    (void)aclInfo;
    (void)userKeyInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t GetUserKeyInfoDiffAccountWithUserLevel(const AuthACLInfo *aclInfo, AuthUserKeyInfo *userKeyInfo)
{
    (void)aclInfo;
    (void)userKeyInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t GetUserKeyInfoDiffAccount(const AuthACLInfo *aclInfo, AuthUserKeyInfo *userKeyInfo)
{
    (void)aclInfo;
    (void)userKeyInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t GetUserKeyInfoGroupShare(const AuthACLInfo *aclInfo, AuthUserKeyInfo *userKeyInfo)
{
    (void)aclInfo;
    (void)userKeyInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t GetUserKeyByUkId(int32_t sessionKeyId, uint8_t *uk, uint32_t ukLen)
{
    (void)sessionKeyId;
    (void)uk;
    (void)ukLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t InitUkNegoInstanceList(void)
{
    return SOFTBUS_OK;
}

void DeInitUkNegoInstanceList(void)
{
}
