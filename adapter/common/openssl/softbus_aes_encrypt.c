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

#include "softbus_aes_encrypt.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <securec.h>

#include "openssl/aes.h"

#include "softbus_adapter_crypto.h"
#include "softbus_adapter_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"

#define AES_128_CFB_KEYLEN   16
#define AES_256_CFB_KEYLEN   32
#define AES_128_GCM_KEYLEN   16
#define AES_256_GCM_KEYLEN   32
#define AES_128_CFB_BITS_LEN 128
#define AES_256_CFB_BITS_LEN 256
#define OPENSSL_EVP_PADDING_FUNC_OPEN  (1)
#define OPENSSL_EVP_PADDING_FUNC_CLOSE (0)

int32_t SoftBusGenerateHmacHash(const EncryptKey *randomKey, const uint8_t *rootKey, uint32_t rootKeyLen,
    uint8_t *hash, uint32_t hashLen)
{
    uint32_t outBufLen;
    uint8_t tempOutputData[EVP_MAX_MD_SIZE];

    if (randomKey == NULL || rootKey == NULL || rootKeyLen == 0 || hash == NULL || hashLen == 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "HMAC_CTX_new failed.");
        return SOFTBUS_ERR;
    }
    if (HMAC_CTX_reset(ctx) != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "HMAC_CTX_reset failed.");
        HMAC_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    if (HMAC_Init_ex(ctx, rootKey, rootKeyLen, EVP_sha256(), NULL) != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "HMAC_Init_ex failed.");
        HMAC_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    if (HMAC_Update(ctx, randomKey->key, (size_t)randomKey->len) != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "HMAC_Update failed.");
        HMAC_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    if (HMAC_Final(ctx, tempOutputData, &outBufLen) != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "HMAC_Final failed.");
        HMAC_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    HMAC_CTX_free(ctx);
    if (hashLen < outBufLen) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "hash is invalid para.");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(hash, hashLen, tempOutputData, outBufLen) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "hash result memcpy_s failed.");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t OpensslAesCfbEncrypt(
    AesCipherKey *cipherKey, const uint8_t *srcData, uint32_t srcDataLen, uint8_t *outData, uint32_t *outDataLen)
{
    int32_t num = 0;
    int32_t len = 0;
    AES_KEY aes;

    if (cipherKey == NULL || srcData == NULL || srcDataLen == 0 || outData == NULL || outDataLen == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t bits = 0;
    switch (cipherKey->keyLen) {
        case AES_128_CFB_KEYLEN:
            bits = AES_128_CFB_BITS_LEN;
            break;
        case AES_256_CFB_KEYLEN:
            bits = AES_256_CFB_BITS_LEN;
            break;
        default:
            HILOG_ERROR(SOFTBUS_HILOG_ID, "cipherKey->keyLen unable to get encryption bits.");
            return SOFTBUS_INVALID_PARAM;
    }
    if (AES_set_encrypt_key(cipherKey->key, bits, &aes) < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftbusAesCfbEncrypt unable to set encryption key in AES.");
        return SOFTBUS_ERR;
    }
    len = srcDataLen;
    AES_cfb128_encrypt(srcData, outData, len, &aes, cipherKey->iv, &num, ENCRYPT_MODE);
    *outDataLen = srcDataLen;
    return SOFTBUS_OK;
}

static int32_t OpensslAesCfbDecrypt(
    AesCipherKey *cipherKey, const uint8_t *srcData, uint32_t srcDataLen, uint8_t *outData, uint32_t *outDataLen)
{
    int32_t num = 0;
    int32_t len = 0;
    AES_KEY aes;

    if (cipherKey == NULL || srcData == NULL || srcDataLen == 0 || outData == NULL || outDataLen == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t bits = 0;
    switch (cipherKey->keyLen) {
        case AES_128_CFB_KEYLEN:
            bits = AES_128_CFB_BITS_LEN;
            break;
        case AES_256_CFB_KEYLEN:
            bits = AES_256_CFB_BITS_LEN;
            break;
        default:
            HILOG_ERROR(SOFTBUS_HILOG_ID, "cipherKey->keyLen unable to get decryption bits.");
            return SOFTBUS_INVALID_PARAM;
    }
    if (AES_set_encrypt_key(cipherKey->key, bits, &aes) < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SoftbusAesCfbDecrypt unable to set decryption key in AES.");
        return SOFTBUS_ERR;
    }
    len = srcDataLen;
    AES_cfb128_encrypt(srcData, outData, len, &aes, cipherKey->iv, &num, DECRYPT_MODE);
    *outDataLen = srcDataLen;
    return SOFTBUS_OK;
}

static int32_t RootKeyGenerateIvAndSessionKey(const EncryptKey *randomKey, EncryptKey *rootKey, AesCipherKey *cipherKey)
{
    if (randomKey == NULL || randomKey->key == NULL || rootKey == NULL || rootKey->key == NULL || cipherKey == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    HILOG_DEBUG(SOFTBUS_HILOG_ID, "RootKeyGenerateIvAndSessionKey invoked.");

    uint8_t result[SHA256_MAC_LEN] = { 0 };
    if (SoftBusGenerateHmacHash(randomKey, rootKey->key, rootKey->len, result, sizeof(result)) != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "SslHmacSha256 failed.");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(cipherKey->key, cipherKey->keyLen, result, AES_SESSION_KEY_LENGTH) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "RootKeyGenerateIvAndSessionKey fill sessionKey failed!");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(cipherKey->iv, cipherKey->ivLen, result + AES_SESSION_KEY_LENGTH,
            SHA256_MAC_LEN - AES_SESSION_KEY_LENGTH) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "RootKeyGenerateIvAndSessionKey fill iv failed!");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GenerateIvAndSessionKey(const EncryptKey *randomKey, EncryptKey *rootKey, AesCipherKey *cipherKey)
{
    if (randomKey == NULL || rootKey == NULL || cipherKey == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    cipherKey->keyLen = AES_SESSION_KEY_LENGTH;
    cipherKey->ivLen = AES_IV_LENGTH;
    cipherKey->key = (uint8_t *)SoftBusCalloc(cipherKey->keyLen);
    if (cipherKey->key == NULL) {
        return SOFTBUS_MEM_ERR;
    }
    cipherKey->iv = (uint8_t *)SoftBusCalloc(cipherKey->ivLen);
    if (cipherKey->iv == NULL) {
        SoftBusFree(cipherKey->key);
        return SOFTBUS_MEM_ERR;
    }
    if (RootKeyGenerateIvAndSessionKey(randomKey, rootKey, cipherKey) != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "RootKeyGenerateIvAndSessionKey failed!");
        SoftBusFree(cipherKey->key);
        SoftBusFree(cipherKey->iv);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusAesCfbRootEncrypt(const AesInputData *inData, const EncryptKey *randomKey, EncryptKey *rootKey,
    int32_t encMode, AesOutputData *outData)
{
    int32_t ret = SOFTBUS_OK;
    AesCipherKey cipherKey = { 0 };

    if (inData == NULL || inData->data == NULL || randomKey == NULL || rootKey == NULL || outData == NULL ||
        (encMode != ENCRYPT_MODE && encMode != DECRYPT_MODE)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t encryptDataLen = inData->len;
    uint8_t *encryptData = (uint8_t *)SoftBusCalloc(encryptDataLen);
    if (encryptData == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "encrypt data calloc fail.");
        return SOFTBUS_MEM_ERR;
    }
    if (GenerateIvAndSessionKey(randomKey, rootKey, &cipherKey) != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "GenerateIvAndSessionKey failed!");
        SoftBusFree(encryptData);
        return SOFTBUS_ERR;
    }
    if (encMode == ENCRYPT_MODE) {
        if (OpensslAesCfbEncrypt(&cipherKey, inData->data, inData->len, encryptData, &encryptDataLen) != SOFTBUS_OK) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "OpensslAesCfbEncrypt by root key failed.");
            ret = SOFTBUS_ENCRYPT_ERR;
            goto EXIT;
        }
    } else {
        if (OpensslAesCfbDecrypt(&cipherKey, inData->data, inData->len, encryptData, &encryptDataLen) != SOFTBUS_OK) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "OpensslAesCfbDecrypt by root key failed.");
            ret = SOFTBUS_ERR;
            goto EXIT;
        }
    }
    SoftBusFree(cipherKey.key);
    SoftBusFree(cipherKey.iv);
    outData->len = encryptDataLen;
    outData->data = encryptData;
    return SOFTBUS_OK;

EXIT:
    SoftBusFree(cipherKey.key);
    SoftBusFree(cipherKey.iv);
    SoftBusFree(encryptData);
    return ret;
}

static EVP_CIPHER *GetSslGcmAlgorithmByKeyLen(uint32_t keyLen)
{
    switch (keyLen) {
        case AES_128_GCM_KEYLEN:
            return (EVP_CIPHER *)EVP_aes_128_gcm();
        case AES_256_GCM_KEYLEN:
            return (EVP_CIPHER *)EVP_aes_256_gcm();
        default:
            HILOG_ERROR(SOFTBUS_HILOG_ID, "Get SslGcmAlgorithm ByKeyLen failed.");
            return NULL;
    }
    return NULL;
}

static int32_t GcmOpensslEvpInit(EVP_CIPHER_CTX **ctx, uint32_t keyLen, int32_t cipherMode)
{
    if (ctx == NULL || keyLen == 0 || (cipherMode != ENCRYPT_MODE && cipherMode != DECRYPT_MODE)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    HILOG_DEBUG(SOFTBUS_HILOG_ID, "GcmOpensslEvpInit invoked.");
    EVP_CIPHER *cipher = GetSslGcmAlgorithmByKeyLen(keyLen);
    if (cipher == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "GetSslGcmAlgorithmByKeyLen failed.");
        return SOFTBUS_ERR;
    }
    *ctx = EVP_CIPHER_CTX_new();
    if (*ctx == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_CIPHER_CTX_new failed.");
        return SOFTBUS_ERR;
    }
    EVP_CIPHER_CTX_set_padding(*ctx, OPENSSL_EVP_PADDING_FUNC_CLOSE);
    if (cipherMode == ENCRYPT_MODE) {
        if (EVP_EncryptInit_ex(*ctx, cipher, NULL, NULL, NULL) != 1) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_EncryptInit_ex failed.");
            EVP_CIPHER_CTX_free(*ctx);
            return SOFTBUS_ERR;
        }
    } else {
        if (EVP_DecryptInit_ex(*ctx, cipher, NULL, NULL, NULL) != 1) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_DecryptInit_ex failed.");
            EVP_CIPHER_CTX_free(*ctx);
            return SOFTBUS_ERR;
        }
    }
    if (EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LENGTH, NULL) != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_CIPHER_CTX_ctrl failed.");
        EVP_CIPHER_CTX_free(*ctx);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t OpensslAesGcmEncrypt(
    const uint8_t *srcData, uint32_t srcDataLen, AesCipherKey *cipherKey, uint8_t *outData, uint32_t *outDataLen)
{
    if (srcData == NULL || srcDataLen == 0 || cipherKey == NULL || outData == NULL || outDataLen == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    EVP_CIPHER_CTX *ctx = NULL;
    if (GcmOpensslEvpInit(&ctx, cipherKey->keyLen, ENCRYPT_MODE) != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "GcmOpensslEvpInit failed.");
        return SOFTBUS_ERR;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, cipherKey->key, cipherKey->iv) != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_EncryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    int32_t outLen = 0;
    int32_t outBufLen = 0;
    if (EVP_EncryptUpdate(ctx, outData, &outBufLen, srcData, srcDataLen) != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_EncryptUpdate failed.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    outLen += outBufLen;
    if (EVP_EncryptFinal_ex(ctx, outData + outBufLen, &outBufLen) != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_EncryptFinal_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    outLen += outBufLen;
    if (*outDataLen < ((uint32_t)outLen + GCM_OVERHEAD_LEN)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "Encrypt invalid para.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    uint8_t tagbuf[AES_GCM_TAG_LEN]; // outData has two part: EncryptedData & AES-GCM-TAG
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, (void *)tagbuf) != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_CTRL_GCM_GET_TAG failed.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    if (memcpy_s(outData + outLen, *outDataLen - outLen, tagbuf, AES_GCM_TAG_LEN) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "tag memcpy_s failed.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    *outDataLen = outLen + AES_GCM_TAG_LEN;
    EVP_CIPHER_CTX_free(ctx);
    return SOFTBUS_OK;
}

static int32_t OpensslAesGcmDecrypt(
    const uint8_t *srcData, uint32_t srcDataLen, AesCipherKey *cipherKey, uint8_t *outData, uint32_t *outDataLen)
{
    if (srcData == NULL || srcDataLen <= AES_GCM_TAG_LEN || cipherKey == NULL || outData == NULL ||
        outDataLen == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    HILOG_DEBUG(SOFTBUS_HILOG_ID, "OpensslAesGcmDecrypt invoked.");
    EVP_CIPHER_CTX *ctx = NULL;
    if (GcmOpensslEvpInit(&ctx, cipherKey->keyLen, DECRYPT_MODE) != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "GcmOpensslEvpInit failed.");
        return SOFTBUS_ERR;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, cipherKey->key, cipherKey->iv) != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_DecryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    int32_t outLen = 0;
    int32_t outBufLen = 0;
    uint8_t trueEncryptedData[srcDataLen - AES_GCM_TAG_LEN];
    if (memcpy_s(trueEncryptedData, srcDataLen - AES_GCM_TAG_LEN, srcData, srcDataLen - AES_GCM_TAG_LEN) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "trueEncryptedData memcpy_s failed.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, (void *)(srcData + (srcDataLen - AES_GCM_TAG_LEN))) != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_CTRL_GCM_SET_TAG failed.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    if (EVP_DecryptUpdate(ctx, outData, &outBufLen, trueEncryptedData, srcDataLen - AES_GCM_TAG_LEN) != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_DecryptUpdate failed.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    outLen += outBufLen;
    if (EVP_DecryptFinal_ex(ctx, outData + outBufLen, &outBufLen) != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_EncryptFinal_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_ERR;
    }
    outLen += outBufLen;
    *outDataLen = outLen;
    EVP_CIPHER_CTX_free(ctx);
    return SOFTBUS_OK;
}

int32_t SoftbusAesGcmEncrypt(
    const AesInputData *inData, AesCipherKey *cipherKey, int32_t encMode, AesOutputData *outData)
{
    if (inData == NULL || inData->data == NULL || cipherKey == NULL || outData == NULL ||
        (encMode != ENCRYPT_MODE && encMode != DECRYPT_MODE)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t encryptDataLen = inData->len + GCM_OVERHEAD_LEN;
    uint8_t *encryptData = (uint8_t *)SoftBusCalloc(encryptDataLen);
    if (encryptData == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "encrypt data calloc fail.");
        return SOFTBUS_MEM_ERR;
    }
    if (encMode == ENCRYPT_MODE) {
        if (OpensslAesGcmEncrypt(inData->data, inData->len, cipherKey, encryptData, &encryptDataLen) != SOFTBUS_OK) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "OpensslAesCfbEncrypt failed.");
            SoftBusFree(encryptData);
            return SOFTBUS_ERR;
        }
    } else {
        if (OpensslAesGcmDecrypt(inData->data, inData->len, cipherKey, encryptData, &encryptDataLen) != SOFTBUS_OK) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "OpensslAesCfbDecrypt failed.");
            SoftBusFree(encryptData);
            return SOFTBUS_ERR;
        }
    }
    outData->data = encryptData;
    outData->len = encryptDataLen;
    return SOFTBUS_OK;
}

int32_t SoftbusAesCfbEncrypt(
    const AesInputData *inData, AesCipherKey *cipherKey, int32_t encMode, AesOutputData *outData)
{
    return SOFTBUS_NOT_IMPLEMENT;
}