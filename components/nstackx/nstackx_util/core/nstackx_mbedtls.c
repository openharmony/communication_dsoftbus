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

#ifdef MBEDTLS_INCLUDED
#include "nstackx_mbedtls.h"
#include "nstackx_error.h"
#include "nstackx_log.h"
#include "securec.h"

#define TAG "nStackXMbedtls"

static pthread_mutex_t g_randomLock = PTHREAD_MUTEX_INITIALIZER;
static mbedtls_entropy_context g_mbedtlsEntropy;
static mbedtls_ctr_drbg_context g_mbedtlsCtrDrbg;

MBEDTLS_CTX *CreateCryptCtx(void)
{
    LOGI(TAG, "mbedtls CreateCryptCtx");
    return &g_mbedtlsCtrDrbg;
}

void ClearCryptCtx(MBEDTLS_CTX *ctx)
{
    (void)ctx;
    return;
}

static int32_t MbedtlsGetRandomSeed(void)
{
    static int inited = 0;

    if (inited == 0) {
        mbedtls_ctr_drbg_init(&g_mbedtlsCtrDrbg);
        mbedtls_entropy_init(&g_mbedtlsEntropy);
        int ret = mbedtls_ctr_drbg_seed(&g_mbedtlsCtrDrbg, mbedtls_entropy_func, &g_mbedtlsEntropy, NULL, 0);
        if (ret != 0) {
            LOGE(TAG, "gen random seed error, ret[%d]", ret);
            return NSTACKX_EFAILED;
        }
        inited = 1;
    }
    return NSTACKX_EOK;
}

int32_t GetRandBytes(uint8_t *buf, uint32_t len)
{
    int ret;
    if (buf == NULL || len == 0) {
        LOGE(TAG, "buf is NULL or illegal length %u", len);
        return NSTACKX_EFAILED;
    }

    if (pthread_mutex_lock(&g_randomLock) != 0) {
        LOGE(TAG, "lock failed");
        return NSTACKX_EFAILED;
    }
    if (MbedtlsGetRandomSeed() != NSTACKX_EOK) {
        LOGE(TAG, "MbedtlsGetRandomSeed error");
        if (pthread_mutex_unlock(&g_randomLock) != 0) {
            LOGE(TAG, "unlock failed");
        }
        return NSTACKX_EFAILED;
    }

    ret = mbedtls_ctr_drbg_random(&g_mbedtlsCtrDrbg, buf, len);
    if (ret != 0) {
        LOGE(TAG, "gen random error, ret[%d]", ret);
        ret = NSTACKX_EFAILED;
    }

    if (pthread_mutex_unlock(&g_randomLock) != 0) {
        LOGE(TAG, "unlock failed");
        return NSTACKX_EFAILED;
    }
    return ret;
}

static uint32_t MbedAesGcmEncrypt(const CryptPara *cryptPara, const uint8_t *inBuf,
    uint32_t inLen, uint8_t *outBuf, uint32_t outLen)
{
    if ((cryptPara == NULL) || (inBuf == NULL) || (inLen == 0) || outBuf == NULL ||
        (outLen < inLen + GCM_ADDED_LEN)) {
        LOGE(TAG, "Encrypt invalid para");
        return 0;
    }

    int ret;
    unsigned char tagBuf[GCM_TAG_LENGTH] = {0};
    mbedtls_gcm_context aesContext;
    mbedtls_gcm_init(&aesContext);

    ret = mbedtls_gcm_setkey(&aesContext, MBEDTLS_CIPHER_ID_AES, cryptPara->key, cryptPara->keylen * KEY_BITS_UNIT);
    if (ret != 0) {
        mbedtls_gcm_free(&aesContext);
        return 0;
    }

    ret = mbedtls_gcm_crypt_and_tag(&aesContext, MBEDTLS_GCM_ENCRYPT, inLen, cryptPara->iv,
        GCM_IV_LENGTH, cryptPara->aad, cryptPara->aadLen, inBuf, outBuf, GCM_TAG_LENGTH, tagBuf);
    if (ret != 0) {
        mbedtls_gcm_free(&aesContext);
        return 0;
    }

    if (memcpy_s(outBuf + inLen, outLen - inLen, tagBuf, GCM_TAG_LENGTH) != 0) {
        mbedtls_gcm_free(&aesContext);
        return 0;
    }

    if (memcpy_s(outBuf + inLen + GCM_TAG_LENGTH, GCM_IV_LENGTH, cryptPara->iv, GCM_IV_LENGTH) != 0) {
        mbedtls_gcm_free(&aesContext);
        return 0;
    }

    mbedtls_gcm_free(&aesContext);
    return (inLen + GCM_ADDED_LEN);
}

static uint32_t MbedChaChaEncrypt(const CryptPara *cryptPara, const uint8_t *inBuf,
    uint32_t inLen, uint8_t *outBuf, uint32_t outLen)
{
    unsigned char tagBuf[GCM_TAG_LENGTH] = {0};
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    int ret = mbedtls_chachapoly_setkey(&ctx, cryptPara->key);
    if (ret != 0) {
        LOGE(TAG, "set key fail, ret %d", ret);
        mbedtls_chachapoly_free(&ctx);
        return 0;
    }
    ret = mbedtls_chachapoly_encrypt_and_tag(&ctx, inLen, cryptPara->iv,
        cryptPara->aad, cryptPara->aadLen, inBuf, outBuf, tagBuf);
    if (ret != 0) {
        LOGE(TAG, "encrypt data fail, ret %d", ret);
        mbedtls_chachapoly_free(&ctx);
        return 0;
    }

    if (memcpy_s(outBuf + inLen, outLen - inLen, tagBuf, GCM_TAG_LENGTH) != 0) {
        mbedtls_chachapoly_free(&ctx);
        return 0;
    }

    if (memcpy_s(outBuf + inLen + GCM_TAG_LENGTH, GCM_IV_LENGTH, cryptPara->iv, GCM_IV_LENGTH) != 0) {
        mbedtls_chachapoly_free(&ctx);
        return 0;
    }

    mbedtls_chachapoly_free(&ctx);
    return (inLen + GCM_ADDED_LEN);
}

uint32_t AesGcmEncrypt(const uint8_t *inBuf, uint32_t inLen, CryptPara *cryptPara, uint8_t *outBuf,
                       uint32_t outLen)
{
    if (outLen <= GCM_ADDED_LEN || cryptPara == NULL || outBuf == NULL) {
        return 0;
    }
    cryptPara->ivLen = GCM_IV_LENGTH;

    if (GetRandBytes(cryptPara->iv, cryptPara->ivLen) != NSTACKX_EOK) {
        LOGE(TAG, "get rand iv failed");
        return 0;
    }
    if (cryptPara->cipherType == CIPHER_CHACHA) {
        return MbedChaChaEncrypt(cryptPara, inBuf, inLen, outBuf, outLen);
    }
    return MbedAesGcmEncrypt(cryptPara, inBuf, inLen, outBuf, outLen);
}

static uint32_t MbedAesGcmDecrypt(const CryptPara *cryptPara, uint8_t *inBuf, uint32_t inLen,
                                  uint8_t *outBuf, uint32_t outLen)
{
    if ((cryptPara == NULL) || (inBuf == NULL) || (inLen <= GCM_ADDED_LEN) || outBuf == NULL ||
        (outLen < inLen - GCM_ADDED_LEN)) {
        LOGE(TAG, "Decrypt invalid para");
        return 0;
    }

    mbedtls_gcm_context aesContext;
    mbedtls_gcm_init(&aesContext);
    int ret = mbedtls_gcm_setkey(&aesContext, MBEDTLS_CIPHER_ID_AES, cryptPara->key,
        cryptPara->keylen * KEY_BITS_UNIT);
    if (ret != 0) {
        LOGE(TAG, "Decrypt mbedtls_gcm_setkey fail");
        mbedtls_gcm_free(&aesContext);
        return 0;
    }

    int actualPlainLen = inLen - GCM_ADDED_LEN;
    ret = mbedtls_gcm_auth_decrypt(&aesContext, inLen - GCM_ADDED_LEN, cryptPara->iv, GCM_IV_LENGTH,
        cryptPara->aad, cryptPara->aadLen, inBuf + actualPlainLen, GCM_TAG_LENGTH, inBuf, outBuf);
    if (ret != 0) {
        LOGE(TAG, "Decrypt mbedtls_gcm_auth_decrypt fail");
        mbedtls_gcm_free(&aesContext);
        return 0;
    }

    mbedtls_gcm_free(&aesContext);
    return actualPlainLen;
}

static uint32_t MbedChaChaDecrypt(const CryptPara *cryptPara, uint8_t *inBuf, uint32_t inLen,
    uint8_t *outBuf, uint32_t outLen)
{
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    int ret = mbedtls_chachapoly_setkey(&ctx, cryptPara->key);
    if (ret != 0) {
        LOGE(TAG, "set key fail, ret %d", ret);
        mbedtls_chachapoly_free(&ctx);
        return NSTACKX_EFAILED;
    }

    uint32_t actualPlainLen = inLen - GCM_ADDED_LEN;
    ret = mbedtls_chachapoly_encrypt_and_tag(&ctx, inLen - GCM_ADDED_LEN, cryptPara->iv,
        cryptPara->aad, cryptPara->aadLen, inBuf, outBuf, inBuf + actualPlainLen);
    if (ret != 0) {
        LOGE(TAG, "Decrypt mbedtls_chachapoly_encrypt_and_tag fail");
        mbedtls_chachapoly_free(&ctx);
        return 0;
    }

    mbedtls_chachapoly_free(&ctx);
    return actualPlainLen;
}

uint32_t AesGcmDecrypt(uint8_t *inBuf, uint32_t inLen, CryptPara *cryptPara, uint8_t *outBuf,
                       uint32_t outLen)
{
    if (inLen <= GCM_ADDED_LEN || outLen < inLen - GCM_ADDED_LEN || cryptPara == NULL ||
        inBuf == NULL || outBuf == NULL) {
        return 0;
    }
    cryptPara->ivLen = GCM_IV_LENGTH;
    if (memcpy_s(cryptPara->iv, cryptPara->ivLen, inBuf + (inLen - GCM_IV_LENGTH), GCM_IV_LENGTH) != EOK) {
        return 0;
    }

    if (cryptPara->cipherType == CIPHER_CHACHA) {
        return MbedChaChaDecrypt(cryptPara, inBuf, inLen, outBuf, outLen);
    }
    return MbedAesGcmDecrypt(cryptPara, inBuf, inLen, outBuf, outLen);
}

uint8_t IsCryptoIncluded(void)
{
    return NSTACKX_TRUE;
}

uint8_t QueryCipherSupportByName(char *name)
{
    int ret = mbedtls_version_check_feature(name);
    if (ret != NSTACKX_EFAILED) {
        return NSTACKX_TRUE;
    }

    LOGI(TAG, "devices no support %s", name);
    return NSTACKX_FALSE;
}

/* check CPU supports AES-NI hardware optimize */
uint8_t IsSupportHardwareAesNi(void)
{
    LOGI(TAG, "no support AES-NI");
    return NSTACKX_FALSE;
}
#endif // MBEDTLS_INCLUDED
