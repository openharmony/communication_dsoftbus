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
#ifndef LNN_CIPHERKEY_MANAGER_STRUCT_H
#define LNN_CIPHERKEY_MANAGER_STRUCT_H

#include "softbus_common.h"
#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char udid[UDID_BUF_LEN];
    uint64_t endTime;
    BroadcastCipherInfo cipherInfo;
    unsigned char sparkCheck[SPARK_CHECK_LENGTH];
} BroadcastCipherKey;

#ifdef __cplusplus
}
#endif
#endif