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

#ifndef SOFTBUS_CRYPTO_H
#define SOFTBUS_CRYPTO_H

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

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
typedef struct {
    unsigned char *aad;
    unsigned int aadLen;
    const unsigned char *input;
    unsigned int inputLen;
    unsigned char **output;
    unsigned int *outputLen;
} GcmInputParams;

typedef struct {
    unsigned int keyLen;
    unsigned char key[SESSION_KEY_LENGTH];
    unsigned char iv[GCM_IV_LEN];
} AesGcmCipherKey;

int GenerateSessionKey(char* key, int len);

int SoftBusEncryptData(AesGcmCipherKey *key, const unsigned char *input, unsigned int inLen,
    unsigned char *encryptData, unsigned int *encryptLen);

int SoftBusEncryptDataWithSeq(AesGcmCipherKey *cipherKey, const unsigned char *input, unsigned int inLen,
    unsigned char *encryptData, unsigned int *encryptLen, int32_t seqNum);

int SoftBusDecryptData(AesGcmCipherKey *key, const unsigned char *input, unsigned int inLen,
    unsigned char *decryptData, unsigned int *decryptLen);

int SoftBusDecryptDataWithSeq(AesGcmCipherKey *cipherKey, const unsigned char *input, unsigned int inLen,
    unsigned char *encryptData, unsigned int *encryptLen, int32_t seqNum);

#endif

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_CRYPTO_H */