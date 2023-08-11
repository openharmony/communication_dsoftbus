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

#ifndef LNN_CIPHERKEY_MANAGER_H
#define LNN_CIPHERKEY_MANAGER_H

#include <stdint.h>

#include "cJSON.h"
#include "softbus_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t LnnInitCipherKeyManager(void);
void LnnDeinitCipherKeyManager(void);
bool GetCipherKeyByNetworkId(const char *networkId, int32_t seq, uint32_t tableIndex, unsigned char *key,
    int32_t keyLen);
bool GetLocalCipherKey(int32_t seq, uint32_t *tableIndex, unsigned char *key, int32_t keyLen);
void LoadBleBroadcastKey(void);
bool IsCipherManagerFindKey(const char *udid);
bool PackCipherKeySyncMsg(void *json);
void ProcessCipherKeySyncInfo(const void *json, const char *networkId);

#ifdef __cplusplus
}
#endif
#endif // LNN_CIPHERKEY_MANAGER_H
