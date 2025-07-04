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

#ifndef AUTH_APPLY_KEY_STRUCT_H
#define AUTH_APPLY_KEY_STRUCT_H

#include <stdint.h>

#include "common_list.h"
#include "softbus_adapter_crypto.h"
#include "softbus_common.h"
#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define D2D_UDID_HASH_STR_LEN    11
#define D2D_ACCOUNT_HASH_STR_LEN 11
#define D2D_APPLY_KEY_LEN        32

typedef enum {
    BUSINESS_TYPE_D2D = 0,
    BUSINESS_TYPE_MAX,
} RequestBusinessType;

typedef struct {
    RequestBusinessType type;
    char udidHash[D2D_UDID_HASH_STR_LEN];
    char accountHash[D2D_ACCOUNT_HASH_STR_LEN];
    char peerAccountHash[SHA_256_HEX_HASH_LEN];
} RequestBusinessInfo;

typedef struct {
    void (*onGenSuccess)(uint32_t requestId, uint8_t *applyKey, uint32_t applyKeyLen);
    void (*onGenFailed)(uint32_t requestId, int32_t reason);
} GenApplyKeyCallback;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_APPLY_KEY_STRUCT_H */