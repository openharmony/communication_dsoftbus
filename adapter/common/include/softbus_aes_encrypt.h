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

#ifndef SOFTBUS_AES_ENCRYPT_H
#define SOFTBUS_AES_ENCRYPT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ENCRYPT_MODE           1
#define DECRYPT_MODE           0
#define SHA256_MAC_LEN         32
#define AES_SESSION_KEY_LENGTH 16
#define AES_IV_LENGTH          16
#define AES_GCM_TAG_LEN        16
#define RANDOM_LENGTH          8

typedef struct {
    uint8_t *key;
    uint32_t keyLen;
    uint8_t *iv;
    uint32_t ivLen;
} AesCipherKey;

typedef struct {
    const uint8_t *key;
    uint32_t len;
} EncryptKey;

typedef struct {
    const uint8_t *data;
    uint32_t len;
} AesInputData;

typedef struct {
    uint8_t *data;
    uint32_t len;
} AesOutputData;

int32_t SoftBusGenerateHmacHash(
    const EncryptKey *randomKey, const uint8_t *rootKey, uint32_t rootKeyLen, uint8_t *hash, uint32_t hashLen);

// Aes-cfb encrypt and decrypt by randomKey and rootKey
int32_t SoftBusAesCfbRootEncrypt(const AesInputData *inData, const EncryptKey *randomKey, EncryptKey *rootKey,
    int32_t encMode, AesOutputData *outData);

int32_t SoftBusAesCfbEncrypt(
    const AesInputData *inData, AesCipherKey *cipherKey, int32_t encMode, AesOutputData *outData);

int32_t SoftBusAesGcmEncrypt(
    const AesInputData *inData, AesCipherKey *cipherKey, int32_t encMode, AesOutputData *outData);

#ifdef __cplusplus
}
#endif
#endif /* SOFTBUS_AES_ENCRYPT_H */
