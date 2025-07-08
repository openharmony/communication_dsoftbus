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

#include "comm_log.h"
#include "mbedtls/base64.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/platform.h"
#include "softbus_adapter_file.h"
#include "softbus_error_code.h"

#ifndef MBEDTLS_CTR_DRBG_C
#define MBEDTLS_CTR_DRBG_C
#endif

#ifndef MBEDTLS_MD_C
#define MBEDTLS_MD_C
#endif

#ifndef MBEDTLS_SHA256_C
#define MBEDTLS_SHA256_C
#endif

#ifndef MBEDTLS_ENTROPY_C
#define MBEDTLS_ENTROPY_C
#endif

#ifndef MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_CIPHER_MODE_CTR
#endif

#ifndef MBEDTLS_AES_C
#define MBEDTLS_AES_C
#endif

#ifndef MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_C
#endif

#define EVP_AES_128_KEYLEN 16
#define EVP_AES_256_KEYLEN 32
#define BYTES_BIT_NUM 8

static SoftBusMutex g_randomLock;

static mbedtls_cipher_type_t GetCtrAlgorithmByKeyLen(uint32_t keyLen)
{
    switch (keyLen) {
        case EVP_AES_128_KEYLEN:
            return MBEDTLS_CIPHER_ARIA_128_CTR;
        case EVP_AES_256_KEYLEN:
            return MBEDTLS_CIPHER_ARIA_256_CTR;
        default:
            return MBEDTLS_CIPHER_NONE;
    }
    return MBEDTLS_CIPHER_NONE;
}

static int32_t MbedAesGcmEncrypt(const AesGcmCipherKey *cipherKey, const unsigned char *plainText,
    uint32_t plainTextSize, unsigned char *cipherText, uint32_t cipherTextLen)
{
    if ((cipherKey == NULL) || (plainText == NULL) || (plainTextSize == 0) || cipherText == NULL ||
        (cipherTextLen < plainTextSize + OVERHEAD_LEN)) {
        COMM_LOGE(COMM_ADAPTER, "Encrypt invalid para");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t ret;
    unsigned char tagBuf[TAG_LEN] = { 0 };
    mbedtls_gcm_context aesContext;
    mbedtls_gcm_init(&aesContext);

    ret = mbedtls_gcm_setkey(&aesContext, MBEDTLS_CIPHER_ID_AES, cipherKey->key, cipherKey->keyLen * KEY_BITS_UNIT);
    if (ret != 0) {
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_ENCRYPT_ERR;
    }

    ret = mbedtls_gcm_crypt_and_tag(&aesContext, MBEDTLS_GCM_ENCRYPT, plainTextSize, cipherKey->iv, GCM_IV_LEN, NULL, 0,
        plainText, cipherText + GCM_IV_LEN, TAG_LEN, tagBuf);
    if (ret != 0) {
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_ENCRYPT_ERR;
    }

    if (memcpy_s(cipherText, cipherTextLen, cipherKey->iv, GCM_IV_LEN) != EOK) {
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_ENCRYPT_ERR;
    }

    if (memcpy_s(cipherText + GCM_IV_LEN + plainTextSize, cipherTextLen - GCM_IV_LEN - plainTextSize, tagBuf,
        TAG_LEN) != 0) {
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_ENCRYPT_ERR;
    }

    mbedtls_gcm_free(&aesContext);
    return (plainTextSize + OVERHEAD_LEN);
}

static int32_t MbedAesGcmDecrypt(const AesGcmCipherKey *cipherKey, const unsigned char *cipherText,
    uint32_t cipherTextSize, unsigned char *plain, uint32_t plainLen)
{
    if ((cipherKey == NULL) || (cipherText == NULL) || (cipherTextSize <= OVERHEAD_LEN) || plain == NULL ||
        (plainLen < cipherTextSize - OVERHEAD_LEN)) {
        COMM_LOGE(COMM_ADAPTER, "Decrypt invalid para");
        return SOFTBUS_INVALID_PARAM;
    }

    mbedtls_gcm_context aesContext;
    mbedtls_gcm_init(&aesContext);
    int32_t ret =
        mbedtls_gcm_setkey(&aesContext, MBEDTLS_CIPHER_ID_AES, cipherKey->key, cipherKey->keyLen * KEY_BITS_UNIT);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "Decrypt mbedtls_gcm_setkey fail.");
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_DECRYPT_ERR;
    }

    int32_t actualPlainLen = (int32_t)(cipherTextSize - OVERHEAD_LEN);
    ret = mbedtls_gcm_auth_decrypt(&aesContext, cipherTextSize - OVERHEAD_LEN, cipherKey->iv, GCM_IV_LEN, NULL, 0,
        cipherText + actualPlainLen + GCM_IV_LEN, TAG_LEN, cipherText + GCM_IV_LEN, plain);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "[TRANS] Decrypt mbedtls_gcm_auth_decrypt fail. ret=%{public}d", ret);
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_DECRYPT_ERR;
    }

    mbedtls_gcm_free(&aesContext);
    return actualPlainLen;
}

static int32_t HandleError(mbedtls_cipher_context_t *ctx, const char *buf)
{
    if (buf != NULL) {
        COMM_LOGE(COMM_ADAPTER, "buf=%{public}s", buf);
    }
    if (ctx != NULL) {
        mbedtls_cipher_free(ctx);
    }
    return SOFTBUS_DECRYPT_ERR;
}

int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen,
    size_t *olen, const unsigned char *src, size_t slen)
{
    if (dst == NULL || dlen == 0 || olen == NULL || src == NULL || slen == 0) {
        COMM_LOGE(COMM_ADAPTER, "base64 encode invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    return mbedtls_base64_encode(dst, dlen, olen, src, slen);
}

int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen,
    size_t *olen, const unsigned char *src, size_t slen)
{
    if (dst == NULL || dlen == 0 || olen == NULL || src == NULL || slen == 0) {
        COMM_LOGE(COMM_ADAPTER, "base64 decode invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    return mbedtls_base64_decode(dst, dlen, olen, src, slen);
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    if (str == NULL || hash == NULL || len == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info = NULL;
    mbedtls_md_init(&ctx);

    info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info == NULL) {
        mbedtls_md_free(&ctx);
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (mbedtls_md_setup(&ctx, info, 0) != 0) {
        mbedtls_md_free(&ctx);
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (mbedtls_md_starts(&ctx) != 0) {
        mbedtls_md_free(&ctx);
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (mbedtls_md_update(&ctx, str, len) != 0) {
        mbedtls_md_free(&ctx);
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (mbedtls_md_finish(&ctx, hash) != 0) {
        mbedtls_md_free(&ctx);
        return SOFTBUS_ENCRYPT_ERR;
    }

    mbedtls_md_free(&ctx);
    return SOFTBUS_OK;
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

    if (!initFlag) {
        if (SoftBusMutexInit(&g_randomLock, NULL) != SOFTBUS_OK) {
            COMM_LOGE(COMM_ADAPTER, "SoftBusGenerateRandomArray init lock fail");
            return SOFTBUS_LOCK_ERR;
        }
        mbedtls_ctr_drbg_init(&ctrDrbg);
        mbedtls_entropy_init(&entropy);
        ret = mbedtls_ctr_drbg_seed(&ctrDrbg, mbedtls_entropy_func, &entropy, NULL, 0);
        if (ret != 0) {
            SoftBusMutexUnlock(&g_randomLock);
            COMM_LOGE(COMM_ADAPTER, "gen random seed error, ret=%{public}d", ret);
            return SOFTBUS_ERR;
        }
        initFlag = true;
    }

    if (SoftBusMutexLock(&g_randomLock) != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "SoftBusGenerateRandomArray lock fail");
        return SOFTBUS_LOCK_ERR;
    }

    ret = mbedtls_ctr_drbg_random(&ctrDrbg, randStr, len);
    SoftBusMutexUnlock(&g_randomLock);
    if (ret != 0) {
        COMM_LOGE(COMM_ADAPTER, "gen random error, ret=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusGenerateSessionKey(char *key, uint32_t len)
{
    if (SoftBusGenerateRandomArray((unsigned char *)key, len) != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "generate sessionKey error.");
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
        COMM_LOGE(COMM_ADAPTER, "generate random iv error.");
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
        COMM_LOGE(COMM_ADAPTER, "generate random iv error.");
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
        COMM_LOGE(COMM_ADAPTER, "copy iv failed.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    uint32_t outLen = inLen - OVERHEAD_LEN;
    int32_t result = MbedAesGcmDecrypt(cipherKey, input, inLen, decryptData, outLen);
    if (result <= 0) {
        return SOFTBUS_ENCRYPT_ERR;
    }
    *decryptLen = (uint32_t)result;
    return SOFTBUS_OK;
}

int32_t SoftBusDecryptDataWithSeq(AesGcmCipherKey *cipherKey, const unsigned char *input, uint32_t inLen,
    unsigned char *decryptData, uint32_t *decryptLen, int32_t seqNum)
{
    (void)seqNum;
    return SoftBusDecryptData(cipherKey, input, inLen, decryptData, decryptLen);
}

uint32_t SoftBusCryptoRand(void)
{
    int32_t fd = SoftBusOpenFile("/dev/urandom", SOFTBUS_O_RDONLY);
    if (fd < 0) {
        COMM_LOGE(COMM_ADAPTER, "CryptoRand open file fail");
        return 0;
    }
    uint32_t value = 0;
    int32_t len = SoftBusReadFile(fd, &value, sizeof(uint32_t));
    if (len < 0) {
        COMM_LOGE(COMM_ADAPTER, "CryptoRand read file fail");
        SoftBusCloseFile(fd);
        return 0;
    }
    SoftBusCloseFile(fd);
    return value;
}

int32_t SoftBusEncryptDataByCtr(AesCtrCipherKey *key, const unsigned char *input, uint32_t inLen,
    unsigned char *encryptData, uint32_t *encryptLen)
{
    if (key == NULL || input == NULL || inLen == 0 || encryptData == NULL || encryptLen == NULL) {
        COMM_LOGE(COMM_ADAPTER, "softbus encrypt data by ctr invalid para");
        return SOFTBUS_INVALID_PARAM;
    }
    mbedtls_cipher_type_t type = GetCtrAlgorithmByKeyLen(key->keyLen);
    if (type == MBEDTLS_CIPHER_NONE) {
        return HandleError(NULL, "get cipher failed");
    }
    size_t len = 0;
    *encryptLen = 0;
    mbedtls_cipher_context_t ctx;
    const mbedtls_cipher_info_t *info = NULL;
    mbedtls_cipher_init(&ctx);
    if (!(info = mbedtls_cipher_info_from_type(type))) {
        return HandleError(&ctx, "mbedtls_cipher_info_from_type ctr failed");
    }
    if (mbedtls_cipher_setup(&ctx, info) != 0) {
        return HandleError(&ctx, "mbedtls_cipher_setup ctr failed");
    }
    if (mbedtls_cipher_setkey(&ctx, key->key, key->keyLen * BYTES_BIT_NUM, MBEDTLS_ENCRYPT) != 0) {
        return HandleError(&ctx, "mbedtls_cipher_setkey ctr failed");
    }
    if (mbedtls_cipher_set_iv(&ctx, key->iv, BLE_BROADCAST_IV_LEN) != 0) {
        return HandleError(&ctx, "mbedtls_cipher_set_iv ctr failed");
    }
    if (mbedtls_cipher_update(&ctx, input, inLen, encryptData, &len) != 0) {
        return HandleError(&ctx, "mbedtls_cipher_update ctr failed");
    }
    *encryptLen += len;
    if (mbedtls_cipher_finish(&ctx, encryptData, &len) != 0) {
        return HandleError(&ctx, "mbedtls_cipher_finish ctr failed");
    }
    *encryptLen += len;
    mbedtls_cipher_free(&ctx);
    return SOFTBUS_OK;
}

int32_t SoftBusDecryptDataByCtr(AesCtrCipherKey *key, const unsigned char *input, uint32_t inLen,
    unsigned char *decryptData, uint32_t *decryptLen)
{
    return SoftBusEncryptDataByCtr(key, input, inLen, decryptData, decryptLen);
}
