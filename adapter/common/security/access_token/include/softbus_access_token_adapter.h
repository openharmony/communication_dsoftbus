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

#ifndef SOFTBUS_ACCESS_TOKEN_ADAPTER
#define SOFTBUS_ACCESS_TOKEN_ADAPTER

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

typedef int32_t (*PermissionChangeCb)(int32_t state, const char *pkgName, int32_t pid);

typedef enum {
    ACEESS_TOKEN_TYPE_INVALID = -1,
    ACCESS_TOKEN_TYPE_HAP = 0,
    ACCESS_TOKEN_TYPE_NATIVE,
    ACCESS_TOKEN_TYPE_SHELL,
    ACCESS_TOKEN_TYPE_BUTT,
} SoftBusAccessTokenType;

bool SoftBusCheckIsSystemService(uint64_t tokenId);
bool SoftBusCheckIsNormalApp(uint64_t fullTokenId, const char *sessionName);
bool SoftBusCheckIsAccessAndRecordAccessToken(uint64_t tokenId, const char *permission);
int32_t SoftBusCalcPermType(uint64_t fullTokenId, pid_t uid, pid_t pid);
int32_t SoftBusCheckDynamicPermission(uint64_t tokenId);
void SoftBusRegisterDataSyncPermission(
    const uint64_t tokenId, const char *permissionName, const char *pkgName, int32_t pid);
void SoftBusRegisterPermissionChangeCb(PermissionChangeCb cb);
int32_t SoftBusGetAccessTokenType(uint64_t tokenId);
void SoftBusGetTokenNameByTokenType(
    char *tokenName, int32_t nameLen, uint64_t tokenId, SoftBusAccessTokenType tokenType);
int32_t SoftBusCheckDmsServerPermission(uint64_t tokenId);
bool SoftBusCheckIsApp(uint64_t fullTokenId, const char *sessionName);
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_ACCESS_TOKEN_ADAPTER */
