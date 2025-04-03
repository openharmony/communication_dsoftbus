/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef AUTH_USER_COMMON_KEY_H
#define AUTH_USER_COMMON_KEY_H

#include "auth_uk_manager.h"
#include "softbus_common.h"
#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
    uint8_t deviceKey[SESSION_KEY_LENGTH];
    uint32_t keyLen;
    uint64_t time;
    int32_t keyIndex;
} AuthUserKeyInfo;

int32_t AuthUserKeyInit(void);
void DeinitUserKeyList(void);
int32_t AuthInsertUserKey(const AuthACLInfo *aclInfo, const AuthUserKeyInfo *userKeyInfo);
void DelUserKeyByUdid(char *networkId);
int32_t GetUserKeyInfoSameAccount(const AuthACLInfo *aclInfo, AuthUserKeyInfo *userKeyInfo);
int32_t GetUserKeyInfoDiffAccount(const AuthACLInfo *aclInfo, AuthUserKeyInfo *userKeyInfo);
int32_t GetUserKeyByUkId(int32_t sessionKeyId, uint8_t *uk, uint32_t ukLen);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_USER_COMMON_KEY_H */