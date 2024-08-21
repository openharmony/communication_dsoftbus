/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_OPENSSL_H
#define NSTACKX_OPENSSL_H

#include "nstackx_common_header.h"

#ifdef SSL_AND_CRYPTO_INCLUDED
#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif // SSL_AND_CRYPTO_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#define AES_128_KEY_LENGTH 16
#define AES_192_KEY_LENGTH 24
#define AES_256_KEY_LENGTH 32
#define GCM_IV_LENGTH 12
#define GCM_MAX_AAD_LENGTH 64
#define GCM_TAG_LENGTH 16
#define GCM_ADDED_LEN (GCM_IV_LENGTH + GCM_TAG_LENGTH)
#define CHACHA20_KEY_LENGTH 32
#define CHACHA20_POLY1305_NAME "chacha20-poly1305"

#ifndef SSL_AND_CRYPTO_INCLUDED
typedef void EVP_CIPHER_CTX;
#undef GCM_TAG_LENGTH
#define GCM_TAG_LENGTH 0
#undef GCM_ADDED_LEN
#define GCM_ADDED_LEN 0
#endif // SSL_AND_CRYPTO_INCLUDED

typedef struct {
    uint8_t key[AES_256_KEY_LENGTH];
    uint32_t keylen;
    uint8_t iv[GCM_IV_LENGTH];
    uint32_t ivLen;
    uint8_t aad[GCM_MAX_AAD_LENGTH];
    uint32_t aadLen;
    EVP_CIPHER_CTX *ctx;
    uint8_t cipherType;
} CryptPara;

typedef struct {
    const uint8_t *buf;
    uint32_t len;
} AesVec;

NSTACKX_EXPORT EVP_CIPHER_CTX *CreateCryptCtx(void);
NSTACKX_EXPORT void ClearCryptCtx(EVP_CIPHER_CTX *ctx);
NSTACKX_EXPORT uint32_t AesGcmEncryptVec(AesVec *vec, uint32_t vecNum, CryptPara *cryptPara,
    uint8_t *outBuf, uint32_t outLen);
NSTACKX_EXPORT uint32_t AesGcmEncrypt(const uint8_t *inBuff, uint32_t inLen, CryptPara *cryptPara,
    uint8_t *outBuff, uint32_t outLen);
NSTACKX_EXPORT uint32_t AesGcmDecrypt(uint8_t *inBuff, uint32_t inLen, CryptPara *cryptPara,
    uint8_t *outBuff, uint32_t outLen);
NSTACKX_EXPORT int32_t GetRandBytes(uint8_t *buf, uint32_t len);
NSTACKX_EXPORT uint8_t IsCryptoIncluded(void);
NSTACKX_EXPORT uint8_t QueryCipherSupportByName(char *name);
NSTACKX_EXPORT uint8_t IsSupportHardwareAesNi(void);

#ifdef __cplusplus
}
#endif

#endif // NSTACKX_OPENSSL_H
