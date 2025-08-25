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

#ifndef AUTH_APPLY_KEY_MANAGER_H
#define AUTH_APPLY_KEY_MANAGER_H

#include <stdlib.h>

#include "auth_apply_key_process.h"
#include "auth_apply_key_struct.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t InitApplyKeyManager(void);
void DeInitApplyKeyManager(void);
int32_t AuthInsertApplyKey(
    const RequestBusinessInfo *info, const uint8_t *uk, uint32_t ukLen, uint64_t time, char *accountHash);
int32_t GetApplyKeyByBusinessInfo(
    const RequestBusinessInfo *info, uint8_t *uk, uint32_t ukLen, char *accountHash, uint32_t accountHashLen);
int32_t AuthDeleteApplyKey(const RequestBusinessInfo *info);
void AuthRecoveryApplyKey(void);
void AuthClearAccountApplyKey(void);

#ifdef __cplusplus
}
#endif
#endif /* AUTH_APPLY_KEY_MANAGER_H */