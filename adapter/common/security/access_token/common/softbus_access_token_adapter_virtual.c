/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "softbus_access_token_adapter.h"

#include "softbus_error_code.h"

bool SoftBusCheckIsSystemService(uint64_t tokenId)
{
    (void)tokenId;
    return false;
}

bool SoftBusCheckIsNormalApp(uint64_t fullTokenId, const char *sessionName)
{
    (void)fullTokenId;
    (void)sessionName;
    return false;
}

bool SoftBusCheckIsAccessAndRecordAccessToken(uint64_t tokenId, const char *permission)
{
    (void)tokenId;
    (void)permission;
    return false;
}

int32_t SoftBusCalcPermType(uint64_t fullTokenId, pid_t uid, pid_t pid)
{
    (void)fullTokenId;
    (void)uid;
    (void)pid;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

int32_t SoftBusCheckDynamicPermission(uint64_t tokenId)
{
    (void)tokenId;
    return SOFTBUS_PERMISSION_DENIED;
}

void SoftBusRegisterDataSyncPermission(
    const uint64_t tokenId, const char *permissionName, const char *pkgName, int32_t pid)
{
    (void)tokenId;
    (void)permissionName;
    (void)pkgName;
    (void)pid;
}

void SoftBusRegisterPermissionChangeCb(PermissionChangeCb cb)
{
    (void)cb;
}

int32_t SoftBusGetAccessTokenType(uint64_t tokenId)
{
    (void)tokenId;
    return SOFTBUS_FUNC_NOT_SUPPORT;
}

void SoftBusGetTokenNameByTokenType(
    char *tokenName, int32_t nameLen, uint64_t tokenId, SoftBusAccessTokenType tokenType)
{
    (void)tokenName;
    (void)nameLen;
    (void)tokenId;
    (void)tokenType;
}

int32_t SoftBusCheckDmsServerPermission(uint64_t tokenId)
{
    (void)tokenId;
    return SOFTBUS_PERMISSION_DENIED;
}

bool SoftBusCheckIsApp(uint64_t fullTokenId, const char *sessionName)
{
    (void)fullTokenId;
    (void)sessionName;
    return false;
}
