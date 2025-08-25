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

#ifndef AUTH_SESSION_KEY_STRUCT_H
#define AUTH_SESSION_KEY_STRUCT_H

#include <stdint.h>
#include "common_list.h"
#include "softbus_adapter_crypto.h"
#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define ENCRYPT_INDEX_LEN 4
#define ENCRYPT_OVER_HEAD_LEN (OVERHEAD_LEN + ENCRYPT_INDEX_LEN)

typedef struct {
    uint8_t value[SESSION_KEY_LENGTH];
    uint32_t len;
} SessionKey;

typedef struct {
    const uint8_t *inData;
    uint32_t inLen;
} InDataInfo;
typedef ListNode SessionKeyList;

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_SESSION_KEY_STRUCT_H */