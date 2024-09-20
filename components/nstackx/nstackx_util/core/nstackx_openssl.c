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

#include "nstackx_openssl.h"
#include "nstackx_error.h"
#include "nstackx_log.h"
#include "securec.h"

#if defined(SSL_AND_CRYPTO_INCLUDED) && defined(NSTACKX_WITH_LINUX_STANDARD)
#include <sys/auxv.h>
#endif

#ifdef BUILD_FOR_WINDOWS
#if (defined(_MSC_VER) && !defined(__clang__)) || \
    ((defined(__GNUC__) || defined(__clang__)) && defined(__AES__) && defined(__PCLMUL__))
#if defined(__GNC__)
#include <cpuid.h>
#elif define(_MSC_VER)
#include <intrin.h>
#endif
#include <immintrin.h>

#define WINDOWS_AESNI_SUPPORT
#define WIN_AESNI_ECI_IDX 2
#endif

#ifndef bit_AES
#define bit_AES (1<<25)
#endif
#endif // BUILD_FOR_WINDOWS

#define TAG "nStackXDFile"

#ifdef SSL_AND_CRYPTO_INCLUDED
int32_t GetRandBytes(uint8_t *buf, uint32_t len)
{
    if (buf == NULL || len == 0) {
        LOGE(TAG, "buf is NULL or illegal length %u", len);
        return NSTACKX_EFAILED;
    }
    if (RAND_bytes(buf, (int)len) != 1) {
        LOGE(TAG, "get rand_bytes failed");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

EVP_CIPHER_CTX *CreateCryptCtx()
{
    LOGI(TAG, "openssl CreateCryptCtx");
    EVP_CIPHER_CTX *ctx = NULL;
    ctx = EVP_CIPHER_CTX_new();
    return ctx;
}

void ClearCryptCtx(EVP_CIPHER_CTX *ctx)
{
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
}
static const EVP_CIPHER *GetCipher(CryptPara *cryptPara)
{
    if (cryptPara->cipherType == CIPHER_CHACHA) {
        return EVP_get_cipherbyname(CHACHA20_POLY1305_NAME);
    } else if (cryptPara->cipherType == CIPHER_AES_GCM) {
        switch (cryptPara->keylen) {
            case AES_128_KEY_LENGTH:
                return EVP_aes_128_gcm();
                break;
            case AES_192_KEY_LENGTH:
                return EVP_aes_192_gcm();
                break;
            case AES_256_KEY_LENGTH:
                return EVP_aes_256_gcm();
                break;
            default:
                return NULL;
        }
    }
    return NULL;
}
static int32_t InitEncryptCtx(CryptPara *cryptPara)
{
    int32_t length;
    const EVP_CIPHER *cipher = GetCipher(cryptPara);

    if (cipher == NULL ||cryptPara->aadLen == 0 || cryptPara->ctx == NULL) {
        return NSTACKX_EFAILED;
    }

    cryptPara->ivLen = GCM_IV_LENGTH;

    if (GetRandBytes(cryptPara->iv, cryptPara->ivLen) != NSTACKX_EOK) {
        LOGE(TAG, "get rand iv failed");
        return NSTACKX_EFAILED;
    }

    if (EVP_EncryptInit_ex(cryptPara->ctx, cipher, NULL, cryptPara->key, cryptPara->iv) == 0) {
        LOGE(TAG, "encrypt init error");
        return NSTACKX_EFAILED;
    }
    if (EVP_EncryptUpdate(cryptPara->ctx, NULL, &length, cryptPara->aad, (int32_t)cryptPara->aadLen) == 0) {
        LOGE(TAG, "add aad error");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

uint32_t AesGcmEncryptVec(AesVec *vec, uint32_t vecNum, CryptPara *cryptPara, uint8_t *outBuf,
                          uint32_t outLen)
{
    int32_t length;
    uint32_t retLen = 0;
    if (vecNum == 0 || outLen <= GCM_ADDED_LEN || cryptPara == NULL ||
        vec == NULL || outBuf == NULL) {
        LOGE(TAG, "Invaid para");
        return 0;
    }
    if (InitEncryptCtx(cryptPara) != NSTACKX_EOK) {
        LOGE(TAG, "InitEncryptCtx error");
        return 0;
    }

    for (uint32_t i = 0; i < vecNum; i++) {
        if ((outLen - GCM_ADDED_LEN) < (retLen + vec[i].len)) {
            LOGE(TAG, "outBuf len %u is less to %u bytes input", outLen, retLen + vec[i].len);
            return 0;
        }
        if (EVP_EncryptUpdate(cryptPara->ctx, outBuf + retLen, &length, vec[i].buf, (int32_t)vec[i].len) == 0 ||
            length != (int)vec[i].len) {
            LOGE(TAG, "encrypt data error");
            return 0;
        }
        retLen += (uint32_t)length;
    }
    if (EVP_EncryptFinal_ex(cryptPara->ctx, outBuf + retLen, &length) == 0 || length != 0) {
        LOGE(TAG, "encrypt final error");
        return 0;
    }
    if (EVP_CIPHER_CTX_ctrl(cryptPara->ctx, EVP_CTRL_AEAD_GET_TAG, GCM_TAG_LENGTH, outBuf + retLen) == 0) {
        LOGE(TAG, "get tag error.");
        return 0;
    }
    retLen += GCM_TAG_LENGTH;
    if (memcpy_s(outBuf + retLen, outLen - retLen, cryptPara->iv, cryptPara->ivLen) != EOK) {
        LOGE(TAG, "pad iv error.");
        return 0;
    }
    retLen += cryptPara->ivLen;
    return retLen;
}

uint32_t AesGcmEncrypt(const uint8_t *inBuf, uint32_t inLen, CryptPara *cryptPara, uint8_t *outBuf,
                       uint32_t outLen)
{
    AesVec vec;
    vec.buf = inBuf;
    vec.len = inLen;
    return AesGcmEncryptVec(&vec, 1, cryptPara, outBuf, outLen);
}

static int32_t InitDecryptCtx(CryptPara *cryptPara)
{
    int32_t length;
    const EVP_CIPHER *cipher = GetCipher(cryptPara);

    if (cipher == NULL || cryptPara->ivLen != GCM_IV_LENGTH || cryptPara->aadLen == 0 || cryptPara->ctx == NULL) {
        return NSTACKX_EFAILED;
    }

    if (EVP_DecryptInit_ex(cryptPara->ctx, cipher, NULL, cryptPara->key, cryptPara->iv) == 0) {
        LOGE(TAG, "decrypt init error");
        return NSTACKX_EFAILED;
    }
    if (EVP_DecryptUpdate(cryptPara->ctx, NULL, &length, cryptPara->aad, (int32_t)cryptPara->aadLen) == 0) {
        LOGE(TAG, "decrypt update error");
        return NSTACKX_EFAILED;
    }
    return NSTACKX_EOK;
}

uint32_t AesGcmDecrypt(uint8_t *inBuf, uint32_t inLen, CryptPara *cryptPara, uint8_t *outBuf,
                       uint32_t outLen)
{
    int32_t length;
    int32_t dataLen;
    uint32_t retLen;
    uint8_t buffer[AES_BLOCK_SIZE];
    if (inLen <= GCM_ADDED_LEN || outLen < inLen - GCM_ADDED_LEN || cryptPara == NULL ||
        inBuf == NULL || outBuf == NULL) {
        LOGE(TAG, "Invaid para");
        return 0;
    }
    cryptPara->ivLen = GCM_IV_LENGTH;
    if (memcpy_s(cryptPara->iv, cryptPara->ivLen, inBuf + (inLen - GCM_IV_LENGTH), GCM_IV_LENGTH) != EOK) {
        return 0;
    }

    if (InitDecryptCtx(cryptPara) != NSTACKX_EOK) {
        LOGE(TAG, "InitDecryptCtx error");
        return 0;
    }
    dataLen = (int32_t)(inLen - GCM_ADDED_LEN);
    if (EVP_DecryptUpdate(cryptPara->ctx, outBuf, &length, inBuf, dataLen) == 0 || length != dataLen) {
        LOGE(TAG, "decrypt data error");
        return 0;
    }
    retLen = (uint32_t)length;

    if (EVP_CIPHER_CTX_ctrl(cryptPara->ctx, EVP_CTRL_AEAD_SET_TAG, GCM_TAG_LENGTH, inBuf + dataLen) == 0) {
        LOGE(TAG, "set tag error.");
        return 0;
    }

    if (EVP_DecryptFinal_ex(cryptPara->ctx, buffer, &length) == 0 || length != 0) {
        LOGE(TAG, "data verify error");
        return 0;
    }
    return retLen;
}

uint8_t IsCryptoIncluded(void)
{
    return NSTACKX_TRUE;
}

uint8_t QueryCipherSupportByName(char *name)
{
    if (EVP_get_cipherbyname(name) != NULL) {
        return NSTACKX_TRUE;
    }

    LOGI(TAG, "devices no support %s", name);
    return NSTACKX_FALSE;
}
#ifdef NSTACKX_WITH_LINUX_STANDARD
#define AES_HWCAP (1UL << 3)
#define AES_HWCAP2 (1UL << 0)

static uint8_t CheckAesCapability(void)
{
    uint8_t ret = NSTACKX_FALSE;
    LOGI(TAG, "CheckAesCapability enter");
    unsigned long hwcaps = getauxval(AT_HWCAP);
    unsigned long hwcaps2 = getauxval(AT_HWCAP2);
    if ((hwcaps & AES_HWCAP) || (hwcaps2 & AES_HWCAP2)) {
        ret = NSTACKX_TRUE;
    }
    return ret;
}
#endif

/* check CPU supports AES-NI hardware optimize */
uint8_t IsSupportHardwareAesNi(void)
{
#if defined(_WIN32) || defined(_WIN64)
#if defined(WINDOWS_AESNI_SUPPORT)
    int32_t cpuInfo[] = {0, 0, 0, 0};
    __cpuid(cpuInfo, 1);
    return (cpuInfo[WIN_AESNI_ECI_IDX] & bit_AES) != 0;
#else
    return NSTACKX_TRUE;
#endif // defined(WINDOWS_AESNI_SUPPORT)

#else // linux

#ifdef NSTACKX_WITH_LINUX_STANDARD
    return CheckAesCapability();
#else
    return NSTACKX_FALSE;
#endif

#endif // defined(_WIN32) || defined(_WIN64)
}

#else
int32_t GetRandBytes(uint8_t *buf, uint32_t len)
{
    LOGI(TAG, "encryption not deployed");
    return NSTACKX_EFAILED;
}

EVP_CIPHER_CTX *CreateCryptCtx(void)
{
    LOGI(TAG, "encryption not deployed");
    EVP_CIPHER_CTX *ctx = NULL;
    return ctx;
}

void ClearCryptCtx(EVP_CIPHER_CTX *ctx)
{
    LOGI(TAG, "encryption not deployed");
    (void)ctx;
}

uint32_t AesGcmEncrypt(const uint8_t *inBuf, uint32_t inLen, CryptPara *cryptPara, uint8_t *outBuf,
                       uint32_t outLen)
{
    (void)inBuf;
    (void)inLen;
    (void)cryptPara;
    (void)outBuf;
    (void)outLen;
    LOGI(TAG, "encryption not deployed");
    return 0;
}

uint32_t AesGcmDecrypt(uint8_t *inBuf, uint32_t inLen, CryptPara *cryptPara, uint8_t *outBuf,
                       uint32_t outLen)
{
    (void)inBuf;
    (void)inLen;
    (void)cryptPara;
    (void)outBuf;
    (void)outLen;
    LOGI(TAG, "encryption not deployed");
    return 0;
}

uint8_t IsCryptoIncluded(void)
{
    return NSTACKX_FALSE;
}

uint8_t QueryCipherSupportByName(char *name)
{
    LOGI(TAG, "devices no support %s", name);
    return NSTACKX_FALSE;
}
/* check CPU supports AES-NI hardware optimize */
uint8_t IsSupportHardwareAesNi(void)
{
    LOGI(TAG, "no support AES-NI");
    return NSTACKX_FALSE;
}

#endif // SSL_AND_CRYPTO_INCLUDED
