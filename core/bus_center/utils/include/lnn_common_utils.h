/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef LNN_COMMON_UTILS_H
#define LNN_COMMON_UTILS_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    uint8_t *data;
    uint32_t dataLen;
    uint8_t *key;
    uint32_t keyLen;
} AesGcmInputParam;

bool IsEnableSoftBusHeartbeat(void);
bool IsOOBEState(void);
bool IsScreenUnlock(void);
int32_t LnnEncryptAesGcm(AesGcmInputParam *in, int32_t keyIndex, uint8_t **out, uint32_t *outLen);
int32_t LnnDecryptAesGcm(AesGcmInputParam *in, uint8_t **out, uint32_t *outLen);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LNN_COMMON_UTILS_H */