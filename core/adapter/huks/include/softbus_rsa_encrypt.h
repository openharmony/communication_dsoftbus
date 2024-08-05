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

#ifndef SOFTBUS_RSA_ENCRYPT_H
#define SOFTBUS_RSA_ENCRYPT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const uint8_t *key;
    uint32_t len;
} PublicKey;

#define SOFTBUS_RSA_LEN         2048
#define SOFTBUS_RSA_ENCRYPT_LEN (SOFTBUS_RSA_LEN / 8)
#define SOFTBUS_RSA_PUB_KEY_LEN (SOFTBUS_RSA_ENCRYPT_LEN + 38)

#define RSA_PUB_KEY_LEN_SUBTRACT_ENCRYPT_LEN 38

int32_t SoftBusGetPublicKey(uint8_t *publicKey, uint32_t publicKeyLen);
int32_t SoftBusRsaEncrypt(const uint8_t *srcData, uint32_t srcDataLen, PublicKey *publicKey, uint8_t **encryptedData,
    uint32_t *encryptedDataLen);
int32_t SoftBusRsaDecrypt(
    const uint8_t *srcData, uint32_t srcDataLen, uint8_t **decryptedData, uint32_t *decryptedDataLen);

#ifdef __cplusplus
}
#endif
#endif /* SOFTBUS_RSA_ENCRYPT_H */
