/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_ADAPTER_CRYPTO_H
#define SOFTBUS_ADAPTER_CRYPTO_H

#include <stdint.h>

#include "softbus_def.h"

#ifndef AES_GCM_H
#define AES_GCM_H

#define HUKS_AES_GCM_KEY_LEN 256
#define GCM_IV_LEN 12
#define AAD_LEN 16

#define TAG_LEN 16
#define OVERHEAD_LEN (GCM_IV_LEN + TAG_LEN)

#define GCM_KEY_BITS_LEN_128 128
#define GCM_KEY_BITS_LEN_256 256
#define KEY_BITS_UNIT 8

#define BLE_BROADCAST_IV_LEN 16

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
typedef struct {
    unsigned char *aad;
    uint32_t aadLen;
    const unsigned char *input;
    uint32_t inputLen;
    unsigned char **output;
    uint32_t *outputLen;
} GcmInputParams;

typedef struct {
    uint32_t keyLen;
    unsigned char key[SESSION_KEY_LENGTH];
    unsigned char iv[GCM_IV_LEN];
} AesGcmCipherKey;

typedef struct {
    uint32_t keyLen;
    unsigned char key[SESSION_KEY_LENGTH];
    unsigned char iv[BLE_BROADCAST_IV_LEN];
} AesCtrCipherKey;

int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen,
    size_t *olen, const unsigned char *src, size_t slen);

int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen,
    size_t *olen, const unsigned char *src, size_t slen);

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash);

int32_t SoftBusGenerateSessionKey(char *key, uint32_t len);

int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len);

int32_t SoftBusEncryptData(AesGcmCipherKey *key, const unsigned char *input, uint32_t inLen,
    unsigned char *encryptData, uint32_t *encryptLen);

int32_t SoftBusEncryptDataWithSeq(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *encryptData, uint32_t *encryptLen, int32_t seqNum);

int32_t SoftBusDecryptData(AesGcmCipherKey *key, const unsigned char *input, uint32_t inLen,
    unsigned char *decryptData, uint32_t *decryptLen);

int32_t SoftBusDecryptDataWithSeq(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *encryptData, uint32_t *encryptLen, int32_t seqNum);

uint32_t SoftBusCryptoRand(void);

int32_t SoftBusEncryptDataByCtr(AesCtrCipherKey *key, const unsigned char *input, uint32_t inLen,
    unsigned char *encryptData, uint32_t *encryptLen);

int32_t SoftBusDecryptDataByCtr(AesCtrCipherKey *key, const unsigned char *input, uint32_t inLen,
    unsigned char *decryptData, uint32_t *decryptLen);

#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_ADAPTER_CRYPTO_H */
