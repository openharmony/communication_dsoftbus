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

#ifndef AUTH_APPLY_KEY_PROCESS_H
#define AUTH_APPLY_KEY_PROCESS_H

#include <securec.h>
#include <stdbool.h>
#include <stdint.h>

#include "auth_apply_key_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t AuthFindApplyKey(const RequestBusinessInfo *info, uint8_t *applyKey);
int32_t AuthGenApplyKey(
    const RequestBusinessInfo *info, uint32_t requestId, uint32_t connId, const GenApplyKeyCallback *genCb);
uint32_t GenApplyKeySeq(void);
bool AuthIsApplyKeyExpired(uint64_t time);
int32_t ApplyKeyNegoInit(void);
void ApplyKeyNegoDeinit(void);

#ifdef __cplusplus
}
#endif

#endif // AUTH_APPLY_KEY_PROCESS_H