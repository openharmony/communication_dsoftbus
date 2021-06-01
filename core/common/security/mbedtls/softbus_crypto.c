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
#include "softbus_crypto.h"

#include <securec.h>

#include "mbedtls/gcm.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

static int MbedAesGcmEncrypt(const AesGcmCipherKey *cipherkey, const unsigned char *plainText,
    unsigned int plainTextSize, unsigned char *cipherText, unsigned int cipherTextLen)
{
    if ((cipherkey == NULL) || (plainText == NULL) || (plainTextSize == 0) || cipherText == NULL ||
        (cipherTextLen < plainTextSize + OVERHEAD_LEN)) {
        LOG_ERR("Encrypt invalid para\n");
        return SOFTBUS_INVALID_PARAM;
    }

    int ret;
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

static int MbedAesGcmDecrypt(const AesGcmCipherKey *cipherkey, const unsigned char *cipherText,
    unsigned int cipherTextSize, unsigned char *plain, unsigned int plainLen)
{
    if ((cipherkey == NULL) || (cipherText == NULL) || (cipherTextSize <= OVERHEAD_LEN) || plain == NULL ||
        (plainLen < cipherTextSize - OVERHEAD_LEN)) {
        LOG_ERR("Decrypt invalid para\n");
        return SOFTBUS_INVALID_PARAM;
    }

    mbedtls_gcm_context aesContext;
    mbedtls_gcm_init(&aesContext);
    int ret = mbedtls_gcm_setkey(&aesContext, MBEDTLS_CIPHER_ID_AES, cipherkey->key,
        cipherkey->keyLen * KEY_BITS_UNIT);
    if (ret != 0) {
        LOG_ERR("Decrypt mbedtls_gcm_setkey fail\n");
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_DECRYPT_ERR;
    }

    int actualPlainLen = cipherTextSize - OVERHEAD_LEN;
    ret = mbedtls_gcm_auth_decrypt(&aesContext, cipherTextSize - OVERHEAD_LEN, cipherkey->iv,
        GCM_IV_LEN, NULL, 0, cipherText + actualPlainLen + GCM_IV_LEN, TAG_LEN, cipherText + GCM_IV_LEN, plain);
    if (ret != 0) {
        LOG_ERR("[TRANS] Decrypt mbedtls_gcm_auth_decrypt fail\n");
        mbedtls_gcm_free(&aesContext);
        return SOFTBUS_DECRYPT_ERR;
    }

    mbedtls_gcm_free(&aesContext);
    return actualPlainLen;
}

int GenerateSessionKey(char *key, int len)
{
    if (GenerateRandomArray((unsigned char*)key, len) != SOFTBUS_OK) {
        LOG_ERR("generate sessionKey error.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

int SoftBusEncryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, unsigned int inLen,
    unsigned char *encryptData, unsigned int *encryptLen)
{
    if (cipherKey == NULL || input == NULL || inLen == 0 || encryptData == NULL || encryptLen == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (GenerateRandomArray(cipherKey->iv, sizeof(cipherKey->iv)) != SOFTBUS_OK) {
        LOG_ERR("generate random iv error.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    unsigned int outLen = inLen + OVERHEAD_LEN;
    int result = MbedAesGcmEncrypt(cipherKey, input, inLen, encryptData, outLen);
    if (result <= 0) {
        return SOFTBUS_ENCRYPT_ERR;
    }
    *encryptLen = result;
    return SOFTBUS_OK;
}

int SoftBusEncryptDataWithSeq(AesGcmCipherKey *cipherKey, const unsigned char *input, unsigned int inLen,
    unsigned char *encryptData, unsigned int *encryptLen, int32_t seqNum)
{
    if (cipherKey == NULL || input == NULL || inLen == 0 || encryptData == NULL || encryptLen == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (GenerateRandomArray(cipherKey->iv, sizeof(cipherKey->iv)) != SOFTBUS_OK) {
        LOG_ERR("generate random iv error.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (memcpy_s(cipherKey->iv, sizeof(int32_t), &seqNum, sizeof(int32_t)) != EOK) {
        return SOFTBUS_ENCRYPT_ERR;
    }
    unsigned int outLen = inLen + OVERHEAD_LEN;
    int result = MbedAesGcmEncrypt(cipherKey, input, inLen, encryptData, outLen);
    if (result <= 0) {
        return SOFTBUS_ENCRYPT_ERR;
    }
    *encryptLen = result;
    return SOFTBUS_OK;
}

int SoftBusDecryptData(AesGcmCipherKey *cipherKey, const unsigned char *input, unsigned int inLen,
    unsigned char *decryptData, unsigned int *decryptLen)
{
    if (cipherKey == NULL || input == NULL || inLen < GCM_IV_LEN || decryptData == NULL || decryptLen == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (memcpy_s(cipherKey->iv, sizeof(cipherKey->iv), input, GCM_IV_LEN) != EOK) {
        LOG_ERR("copy iv failed.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    unsigned int outLen = inLen - OVERHEAD_LEN;
    int result = MbedAesGcmDecrypt(cipherKey, input, inLen, decryptData, outLen);
    if (result <= 0) {
        return SOFTBUS_ENCRYPT_ERR;
    }
    *decryptLen = result;
    return SOFTBUS_OK;
}

int SoftBusDecryptDataWithSeq(AesGcmCipherKey *cipherKey, const unsigned char *input, unsigned int inLen,
    unsigned char *decryptData, unsigned int *decryptLen, int32_t seqNum)
{
    return SoftBusDecryptData(cipherKey, input, inLen, decryptData, decryptLen);
}
