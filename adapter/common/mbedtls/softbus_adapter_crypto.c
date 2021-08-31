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
#include "softbus_adapter_crypto.h"

#include <securec.h>

#include "mbedtls/base64.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "softbus_adapter_log.h"
#include "softbus_errcode.h"

#ifndef MBEDTLS_CTR_DRBG_C
#define MBEDTLS_CTR_DRBG_C
#endif

#ifndef MBEDTLS_ENTROPY_C
#define MBEDTLS_ENTROPY_C
#endif

static pthread_mutex_t g_randomLock = PTHREAD_MUTEX_INITIALIZER;

static int32_t MbedAesGcmEncrypt(const AesGcmCipherKey *cipherkey, const unsigned char *plainText,
    uint32_t plainTextSize, unsigned char *cipherText, uint32_t cipherTextLen)
{
    if ((cipherkey == NULL) || (plainText == NULL) || (plainTextSize == 0) || cipherText == NULL ||
        (cipherTextLen < plainTextSize + OVERHEAD_LEN)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "Encrypt invalid para\n");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret;
    unsigned char tagBuf[TAG_LEN] = {0};
    mbedtls_gcm_context aesContext;
    mbedtls_gcm_init(&aesContext);

    ret = mbedtls_gcm_setkey(&aesContext, MBEDTLS_CIPHER_ID_AES, cipherkey->key, cipherkey->keyLen * KEY_BITS_UNIT);
    if (ret != 0) {
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_ENCRYPT_ERR;
    }

    ret = mbedtls_gcm_crypt_and_tag(&aesContext, MBEDTLS_GCM_ENCRYPT, plainTextSize, cipherkey->iv,
        GCM_IV_LEN, NULL, 0, plainText, cipherText + GCM_IV_LEN, TAG_LEN, tagBuf);
    if (ret != 0) {
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_ENCRYPT_ERR;
    }

    if (memcpy_s(cipherText, cipherTextLen, cipherkey->iv, GCM_IV_LEN) != 0) {
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_ENCRYPT_ERR;
    }

    if (memcpy_s(cipherText + GCM_IV_LEN + plainTextSize, cipherTextLen - GCM_IV_LEN - plainTextSize,
        tagBuf, TAG_LEN) != 0) {
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_ENCRYPT_ERR;
    }

    mbedtls_gcm_free(&aesContext);
    return (plainTextSize + OVERHEAD_LEN);
}

static int32_t MbedAesGcmDecrypt(const AesGcmCipherKey *cipherkey, const unsigned char *cipherText,
    uint32_t cipherTextSize, unsigned char *plain, uint32_t plainLen)
{
    if ((cipherkey == NULL) || (cipherText == NULL) || (cipherTextSize <= OVERHEAD_LEN) || plain == NULL ||
        (plainLen < cipherTextSize - OVERHEAD_LEN)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "Decrypt invalid para\n");
        return SOFTBUS_INVALID_PARAM;
    }

    mbedtls_gcm_context aesContext;
    mbedtls_gcm_init(&aesContext);
    int32_t ret = mbedtls_gcm_setkey(&aesContext, MBEDTLS_CIPHER_ID_AES, cipherkey->key,
        cipherkey->keyLen * KEY_BITS_UNIT);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "Decrypt mbedtls_gcm_setkey fail\n");
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_DECRYPT_ERR;
    }

    int32_t actualPlainLen = cipherTextSize - OVERHEAD_LEN;
    ret = mbedtls_gcm_auth_decrypt(&aesContext, cipherTextSize - OVERHEAD_LEN, cipherkey->iv,
        GCM_IV_LEN, NULL, 0, cipherText + actualPlainLen + GCM_IV_LEN, TAG_LEN, cipherText + GCM_IV_LEN, plain);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "[TRANS] Decrypt mbedtls_gcm_auth_decrypt fail.[%d]\n", ret);
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_DECRYPT_ERR;
    }

    mbedtls_gcm_free(&aesContext);
    return actualPlainLen;
}

int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen,
    size_t *olen, const unsigned char *src, size_t slen)
{
    if (dst == NULL || dlen == 0 || olen == NULL || src == NULL || slen == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    return mbedtls_base64_encode(dst, dlen, olen, src, slen);
}

int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen,
    size_t *olen, const unsigned char *src, size_t slen)
{
    if (dst == NULL || dlen == 0 || olen == NULL || src == NULL || slen == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    return mbedtls_base64_decode(dst, dlen, olen, src, slen);
}

int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len)
{
    if (randStr == NULL || len == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    static mbedtls_entropy_context entropy;
    static mbedtls_ctr_drbg_context ctrDrbg;
    static bool initFlag = false;
    int32_t ret;

    if (pthread_mutex_lock(&g_randomLock) != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "lock mutex failed");
        return SOFTBUS_ERR;
    }

    if (initFlag == false) {
        mbedtls_ctr_drbg_init(&ctrDrbg);
        mbedtls_entropy_init(&entropy);
        ret = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy, NULL, 0);
        if (ret != 0) {
            pthread_mutex_unlock(&g_randomLock);
            HILOG_ERROR(SOFTBUS_HILOG_ID, "gen random seed error, ret[%d]", ret);
            return SOFTBUS_ERR;
        }
        initFlag = true;
    }

    ret = mbedtls_ctr_drbg_random(&ctrDrbg, randStr, len);
    pthread_mutex_unlock(&g_randomLock);
    if (ret != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "gen random error, ret[%d]", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusGenerateSessionKey(char *key, int32_t len)
{
    if (SoftBusGenerateRandomArray((unsigned char*)key, len) != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "generate sessionKey error.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusEncryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *encryptData, uint32_t *encryptLen)
{
    if (cipherKey == NULL || input == NULL || inLen == 0 || encryptData == NULL || encryptLen == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (SoftBusGenerateRandomArray(cipherKey->iv, sizeof(cipherKey->iv)) != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "generate random iv error.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    uint32_t outLen = inLen + OVERHEAD_LEN;
    int32_t result = MbedAesGcmEncrypt(cipherKey, input, inLen, encryptData, outLen);
    if (result <= 0) {
        return SOFTBUS_ENCRYPT_ERR;
    }
    *encryptLen = result;
    return SOFTBUS_OK;
}

int32_t SoftBusEncryptDataWithSeq(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *encryptData, uint32_t *encryptLen, int32_t seqNum)
{
    if (cipherKey == NULL || input == NULL || inLen == 0 || encryptData == NULL || encryptLen == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusGenerateRandomArray(cipherKey->iv, sizeof(cipherKey->iv)) != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "generate random iv error.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (memcpy_s(cipherKey->iv, sizeof(int32_t), &seqNum, sizeof(int32_t)) != EOK) {
        return SOFTBUS_ENCRYPT_ERR;
    }
    uint32_t outLen = inLen + OVERHEAD_LEN;
    int32_t result = MbedAesGcmEncrypt(cipherKey, input, inLen, encryptData, outLen);
    if (result <= 0) {
        return SOFTBUS_ENCRYPT_ERR;
    }
    *encryptLen = result;
    return SOFTBUS_OK;
}

int32_t SoftBusDecryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *decryptData, uint32_t *decryptLen)
{
    if (cipherKey == NULL || input == NULL || inLen < GCM_IV_LEN || decryptData == NULL || decryptLen == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (memcpy_s(cipherKey->iv, sizeof(cipherKey->iv), input, GCM_IV_LEN) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "copy iv failed.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    uint32_t outLen = inLen - OVERHEAD_LEN;
    int32_t result = MbedAesGcmDecrypt(cipherKey, input, inLen, decryptData, outLen);
    if (result <= 0) {
        return SOFTBUS_ENCRYPT_ERR;
    }
    *decryptLen = result;
    return SOFTBUS_OK;
}

int32_t SoftBusDecryptDataWithSeq(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *decryptData, uint32_t *decryptLen, int32_t seqNum)
{
    return SoftBusDecryptData(cipherKey, input, inLen, decryptData, decryptLen);
}