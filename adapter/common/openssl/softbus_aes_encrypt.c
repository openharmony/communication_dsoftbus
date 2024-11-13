/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "comm_log.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

#define AES_128_CFB_KEYLEN             16
#define AES_256_CFB_KEYLEN             32
#define AES_128_GCM_KEYLEN             16
#define AES_256_GCM_KEYLEN             32
#define AES_128_CFB_BITS_LEN           128
#define AES_256_CFB_BITS_LEN           256
#define OPENSSL_EVP_PADDING_FUNC_OPEN  (1)
#define OPENSSL_EVP_PADDING_FUNC_CLOSE (0)

int32_t SoftBusGenerateHmacHash(
    const EncryptKey *randomKey, const uint8_t *rootKey, uint32_t rootKeyLen, uint8_t *hash, uint32_t hashLen)
{
    uint32_t outBufLen;
    uint8_t tempOutputData[EVP_MAX_MD_SIZE];

    if (randomKey == NULL || rootKey == NULL || rootKeyLen == 0 || hash == NULL || hashLen < SHA256_MAC_LEN) {
        COMM_LOGE(COMM_ADAPTER, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        COMM_LOGE(COMM_ADAPTER, "HMAC_CTX_new failed.");
        return SOFTBUS_HMAC_ERR;
    }
    if (HMAC_CTX_reset(ctx) != 1) {
        COMM_LOGE(COMM_ADAPTER, "HMAC_CTX_reset failed.");
        HMAC_CTX_free(ctx);
        return SOFTBUS_HMAC_ERR;
    }
    if (HMAC_Init_ex(ctx, rootKey, rootKeyLen, EVP_sha256(), NULL) != 1) {
        COMM_LOGE(COMM_ADAPTER, "HMAC_Init_ex failed.");
        HMAC_CTX_free(ctx);
        return SOFTBUS_HMAC_ERR;
    }
    if (HMAC_Update(ctx, randomKey->key, (size_t)randomKey->len) != 1) {
        COMM_LOGE(COMM_ADAPTER, "HMAC_Update failed.");
        HMAC_CTX_free(ctx);
        return SOFTBUS_HMAC_ERR;
    }
    if (HMAC_Final(ctx, tempOutputData, &outBufLen) != 1) {
        COMM_LOGE(COMM_ADAPTER, "HMAC_Final failed.");
        HMAC_CTX_free(ctx);
        return SOFTBUS_HMAC_ERR;
    }
    HMAC_CTX_free(ctx);
    if (outBufLen != SHA256_MAC_LEN) {
        COMM_LOGE(COMM_ADAPTER, "outBufLen is invalid length for hash.");
        (void)memset_s(tempOutputData, sizeof(tempOutputData), 0, sizeof(tempOutputData));
        return SOFTBUS_HMAC_ERR;
    }
    if (memcpy_s(hash, hashLen, tempOutputData, outBufLen) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "hash result memcpy_s failed.");
        (void)memset_s(tempOutputData, sizeof(tempOutputData), 0, sizeof(tempOutputData));
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(tempOutputData, sizeof(tempOutputData), 0, sizeof(tempOutputData));
    return SOFTBUS_OK;
}

static int32_t OpensslAesCfbEncrypt(
    AesCipherKey *cipherKey, const AesInputData *inData, int32_t encMode, AesOutputData *outData)
{
    int32_t num = 0;
    AES_KEY aes;

    if (cipherKey == NULL || cipherKey->ivLen != AES_IV_LENGTH || inData == NULL || inData->data == NULL ||
        outData == NULL || (encMode != ENCRYPT_MODE && encMode != DECRYPT_MODE)) {
        COMM_LOGE(COMM_ADAPTER, "invalid param.");
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
            COMM_LOGE(COMM_ADAPTER, "cipherKey->keyLen unable to get encryption bits.");
            return SOFTBUS_INVALID_PARAM;
    }
    if (AES_set_encrypt_key(cipherKey->key, bits, &aes) < 0) {
        COMM_LOGE(COMM_ADAPTER, "SoftbusAesCfbEncrypt unable to set encryption key in AES.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (encMode == ENCRYPT_MODE) {
        AES_cfb128_encrypt(inData->data, outData->data, inData->len, &aes, cipherKey->iv, &num, ENCRYPT_MODE);
    } else {
        AES_cfb128_encrypt(inData->data, outData->data, inData->len, &aes, cipherKey->iv, &num, DECRYPT_MODE);
    }
    outData->len = inData->len;
    OPENSSL_cleanse(&aes, sizeof(aes));
    return SOFTBUS_OK;
}

static int32_t RootKeyGenerateIvAndSessionKey(const EncryptKey *randomKey, EncryptKey *rootKey, AesCipherKey *cipherKey)
{
    uint8_t result[SHA256_MAC_LEN] = { 0 };
    if (SoftBusGenerateHmacHash(randomKey, rootKey->key, rootKey->len, result, sizeof(result)) != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "SslHmacSha256 failed.");
        return SOFTBUS_HMAC_ERR;
    }
    if (memcpy_s(cipherKey->key, cipherKey->keyLen, result, AES_SESSION_KEY_LENGTH) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "RootKeyGenerateIvAndSessionKey fill sessionKey failed!");
        (void)memset_s(result, sizeof(result), 0, sizeof(result));
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(cipherKey->iv, cipherKey->ivLen, result + AES_SESSION_KEY_LENGTH,
            SHA256_MAC_LEN - AES_SESSION_KEY_LENGTH) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "RootKeyGenerateIvAndSessionKey fill iv failed!");
        (void)memset_s(result, sizeof(result), 0, sizeof(result));
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(result, sizeof(result), 0, sizeof(result));
    return SOFTBUS_OK;
}

static int32_t GenerateIvAndSessionKey(const EncryptKey *randomKey, EncryptKey *rootKey, AesCipherKey *cipherKey)
{
    if (cipherKey == NULL) {
        COMM_LOGE(COMM_ADAPTER, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    cipherKey->keyLen = AES_SESSION_KEY_LENGTH;
    cipherKey->ivLen = AES_IV_LENGTH;
    cipherKey->key = (uint8_t *)SoftBusCalloc(cipherKey->keyLen);
    if (cipherKey->key == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    cipherKey->iv = (uint8_t *)SoftBusCalloc(cipherKey->ivLen);
    if (cipherKey->iv == NULL) {
        SoftBusFree(cipherKey->key);
        return SOFTBUS_MALLOC_ERR;
    }
    if (RootKeyGenerateIvAndSessionKey(randomKey, rootKey, cipherKey) != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "RootKeyGenerateIvAndSessionKey failed!");
        (void)memset_s(cipherKey->key, cipherKey->keyLen, 0, cipherKey->keyLen);
        (void)memset_s(cipherKey->iv, cipherKey->ivLen, 0, cipherKey->ivLen);
        SoftBusFree(cipherKey->key);
        SoftBusFree(cipherKey->iv);
        return SOFTBUS_GENERATE_KEY_FAIL;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusAesCfbRootEncrypt(const AesInputData *inData, const EncryptKey *randomKey, EncryptKey *rootKey,
    int32_t encMode, AesOutputData *outData)
{
    if (inData == NULL || inData->data == NULL || randomKey == NULL || randomKey->key == NULL || rootKey == NULL ||
        rootKey->key == NULL || outData == NULL || (encMode != ENCRYPT_MODE && encMode != DECRYPT_MODE)) {
        COMM_LOGE(COMM_ADAPTER, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    AesCipherKey cipherKey = { 0 };
    AesOutputData encryptData = { .data = (uint8_t *)SoftBusCalloc(inData->len), .len = inData->len };
    if (encryptData.data == NULL) {
        COMM_LOGE(COMM_ADAPTER, "encryptData calloc failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (GenerateIvAndSessionKey(randomKey, rootKey, &cipherKey) != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "GenerateIvAndSessionKey failed!");
        SoftBusFree(encryptData.data);
        return SOFTBUS_GENERATE_KEY_FAIL;
    }
    if (OpensslAesCfbEncrypt(&cipherKey, inData, encMode, &encryptData) != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "OpensslAesCfb encrypt or decrypt by root key failed.");
        (void)memset_s(cipherKey.key, cipherKey.keyLen, 0, cipherKey.keyLen);
        (void)memset_s(cipherKey.iv, cipherKey.ivLen, 0, cipherKey.ivLen);
        SoftBusFree(cipherKey.key);
        SoftBusFree(cipherKey.iv);
        SoftBusFree(encryptData.data);
        encryptData.data = NULL;
        return SOFTBUS_ENCRYPT_ERR;
    }
    (void)memset_s(cipherKey.key, cipherKey.keyLen, 0, cipherKey.keyLen);
    (void)memset_s(cipherKey.iv, cipherKey.ivLen, 0, cipherKey.ivLen);
    SoftBusFree(cipherKey.key);
    SoftBusFree(cipherKey.iv);
    outData->len = encryptData.len;
    outData->data = encryptData.data;
    return SOFTBUS_OK;
}

int32_t SoftBusAesCfbEncrypt(
    const AesInputData *inData, AesCipherKey *cipherKey, int32_t encMode, AesOutputData *outData)
{
    uint8_t random[RANDOM_LENGTH] = { 0 };
    uint8_t result[SHA256_MAC_LEN] = { 0 };

    if (inData == NULL || inData->data == NULL || cipherKey == NULL || cipherKey->ivLen < RANDOM_LENGTH ||
        outData == NULL || (encMode != ENCRYPT_MODE && encMode != DECRYPT_MODE)) {
        COMM_LOGE(COMM_ADAPTER, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(random, sizeof(random), cipherKey->iv, sizeof(random)) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "random memcpy_s failed!");
        return SOFTBUS_MEM_ERR;
    }
    EncryptKey key = { cipherKey->key, cipherKey->keyLen };
    if (SoftBusGenerateHmacHash(&key, random, sizeof(random), result, SHA256_MAC_LEN) != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "SslHmacSha256 failed.");
        (void)memset_s(random, sizeof(random), 0, sizeof(random));
        return SOFTBUS_HMAC_ERR;
    }
    (void)memset_s(cipherKey->key, cipherKey->keyLen, 0, cipherKey->keyLen);
    if (memcpy_s(cipherKey->key, cipherKey->keyLen, result, SHA256_MAC_LEN) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "fill cipherKey->key failed!");
        (void)memset_s(random, sizeof(random), 0, sizeof(random));
        (void)memset_s(result, sizeof(result), 0, sizeof(result));
        return SOFTBUS_MEM_ERR;
    }
    AesOutputData encryptData = { .data = (uint8_t *)SoftBusCalloc(inData->len), .len = inData->len };
    if (encryptData.data == NULL) {
        COMM_LOGE(COMM_ADAPTER, "encryptData calloc failed.");
        (void)memset_s(random, sizeof(random), 0, sizeof(random));
        (void)memset_s(result, sizeof(result), 0, sizeof(result));
        return SOFTBUS_MALLOC_ERR;
    }
    if (OpensslAesCfbEncrypt(cipherKey, inData, encMode, &encryptData) != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "OpensslAesCfbEncrypt failed.");
        (void)memset_s(random, sizeof(random), 0, sizeof(random));
        (void)memset_s(result, sizeof(result), 0, sizeof(result));
        SoftBusFree(encryptData.data);
        encryptData.data = NULL;
        return SOFTBUS_ENCRYPT_ERR;
    }

    outData->data = encryptData.data;
    outData->len = encryptData.len;
    return SOFTBUS_OK;
}

static EVP_CIPHER *GetSslGcmAlgorithmByKeyLen(uint32_t keyLen)
{
    switch (keyLen) {
        case AES_128_GCM_KEYLEN:
            return (EVP_CIPHER *)EVP_aes_128_gcm();
        case AES_256_GCM_KEYLEN:
            return (EVP_CIPHER *)EVP_aes_256_gcm();
        default:
            COMM_LOGE(COMM_ADAPTER, "Get SslGcmAlgorithm ByKeyLen failed.");
            return NULL;
    }
    return NULL;
}

static int32_t GcmOpensslEvpInit(EVP_CIPHER_CTX **ctx, uint32_t keyLen, int32_t encMode)
{
    if (ctx == NULL || keyLen == 0 || (encMode != ENCRYPT_MODE && encMode != DECRYPT_MODE)) {
        COMM_LOGE(COMM_ADAPTER, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    EVP_CIPHER *cipher = GetSslGcmAlgorithmByKeyLen(keyLen);
    if (cipher == NULL) {
        COMM_LOGE(COMM_ADAPTER, "GetSslGcmAlgorithmByKeyLen failed.");
        return SOFTBUS_INVALID_PARAM;
    }
    *ctx = EVP_CIPHER_CTX_new();
    if (*ctx == NULL) {
        COMM_LOGE(COMM_ADAPTER, "EVP_CIPHER_CTX_new failed.");
        return SOFTBUS_MALLOC_ERR;
    }
    EVP_CIPHER_CTX_set_padding(*ctx, OPENSSL_EVP_PADDING_FUNC_CLOSE);
    if (encMode == ENCRYPT_MODE) {
        if (EVP_EncryptInit_ex(*ctx, cipher, NULL, NULL, NULL) != 1) {
            COMM_LOGE(COMM_ADAPTER, "EVP_EncryptInit_ex failed.");
            EVP_CIPHER_CTX_free(*ctx);
            *ctx = NULL;
            return SOFTBUS_ENCRYPT_ERR;
        }
    } else {
        if (EVP_DecryptInit_ex(*ctx, cipher, NULL, NULL, NULL) != 1) {
            COMM_LOGE(COMM_ADAPTER, "EVP_DecryptInit_ex failed.");
            EVP_CIPHER_CTX_free(*ctx);
            *ctx = NULL;
            return SOFTBUS_DECRYPT_ERR;
        }
    }
    if (EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_LENGTH, NULL) != 1) {
        COMM_LOGE(COMM_ADAPTER, "EVP_CIPHER_CTX_ctrl failed.");
        EVP_CIPHER_CTX_free(*ctx);
        *ctx = NULL;
        return SOFTBUS_GCM_SET_IV_FAIL;
    }
    return SOFTBUS_OK;
}

static int32_t OpensslAesGcmEncrypt(
    const uint8_t *srcData, uint32_t srcDataLen, AesCipherKey *cipherKey, uint8_t *outData, uint32_t *outDataLen)
{
    if (srcData == NULL || srcDataLen == 0 || cipherKey == NULL || outData == NULL || outDataLen == NULL ||
        *outDataLen < (srcDataLen + AES_GCM_TAG_LEN)) {
        COMM_LOGE(COMM_ADAPTER, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    EVP_CIPHER_CTX *ctx = NULL;
    int32_t ret = GcmOpensslEvpInit(&ctx, cipherKey->keyLen, ENCRYPT_MODE);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_ENCRYPT_ERR, COMM_ADAPTER, "GcmOpensslEvpInit failed.");
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, cipherKey->key, cipherKey->iv) != 1) {
        COMM_LOGE(COMM_ADAPTER, "EVP_EncryptInit_ex failed.");
        goto EXIT;
    }
    int32_t outLen = 0;
    int32_t outBufLen = 0;
    if (EVP_EncryptUpdate(ctx, outData, &outBufLen, srcData, srcDataLen) != 1) {
        COMM_LOGE(COMM_ADAPTER, "EVP_EncryptUpdate failed.");
        goto EXIT;
    }
    outLen += outBufLen;
    if (EVP_EncryptFinal_ex(ctx, outData + outBufLen, &outBufLen) != 1) {
        COMM_LOGE(COMM_ADAPTER, "EVP_EncryptFinal_ex failed.");
        goto EXIT;
    }
    if (outBufLen > INT32_MAX - outLen) {
        COMM_LOGE(COMM_ADAPTER, "outLen convert overflow.");
        goto EXIT;
    }
    outLen += outBufLen;
    if (*outDataLen < ((uint32_t)outLen + AES_GCM_TAG_LEN)) {
        COMM_LOGE(COMM_ADAPTER, "invalid param. *outDataLen=%{public}u, outLen=%{public}u", *outDataLen,
            (uint32_t)outLen);
        goto EXIT;
    }
    uint8_t tagbuf[AES_GCM_TAG_LEN]; // outData has two part: EncryptedData & AES-GCM-TAG
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_LEN, (void *)tagbuf) != 1) {
        COMM_LOGE(COMM_ADAPTER, "EVP_CTRL_GCM_GET_TAG failed.");
        goto EXIT;
    }
    if (memcpy_s(outData + outLen, *outDataLen - outLen, tagbuf, AES_GCM_TAG_LEN) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "tag memcpy_s failed.");
        goto EXIT;
    }
    *outDataLen = outLen + AES_GCM_TAG_LEN;
    EVP_CIPHER_CTX_free(ctx);
    return SOFTBUS_OK;
EXIT:
    EVP_CIPHER_CTX_free(ctx);
    return SOFTBUS_ENCRYPT_ERR;
}

static int32_t OpensslAesGcmDecrypt(
    const uint8_t *srcData, uint32_t srcDataLen, AesCipherKey *cipherKey, uint8_t *outData, uint32_t *outDataLen)
{
    if (srcData == NULL || srcDataLen <= AES_GCM_TAG_LEN || cipherKey == NULL || outData == NULL ||
        outDataLen == NULL || *outDataLen < (srcDataLen - AES_GCM_TAG_LEN)) {
        COMM_LOGE(COMM_ADAPTER, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    EVP_CIPHER_CTX *ctx = NULL;
    if (GcmOpensslEvpInit(&ctx, cipherKey->keyLen, DECRYPT_MODE) != SOFTBUS_OK) {
        COMM_LOGE(COMM_ADAPTER, "GcmOpensslEvpInit failed.");
        return SOFTBUS_DECRYPT_ERR;
    }
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, cipherKey->key, cipherKey->iv) != 1) {
        COMM_LOGE(COMM_ADAPTER, "EVP_DecryptInit_ex failed.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_DECRYPT_ERR;
    }
    int32_t outLen = 0;
    int32_t outBufLen = 0;
    uint8_t trueEncryptedData[srcDataLen - AES_GCM_TAG_LEN];
    if (memcpy_s(trueEncryptedData, srcDataLen - AES_GCM_TAG_LEN, srcData, srcDataLen - AES_GCM_TAG_LEN) != EOK) {
        COMM_LOGE(COMM_ADAPTER, "trueEncryptedData memcpy_s failed.");
        goto EXIT;
    }
    if (EVP_CIPHER_CTX_ctrl(
        ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_LEN, (void *)(srcData + (srcDataLen - AES_GCM_TAG_LEN))) != 1) {
        COMM_LOGE(COMM_ADAPTER, "EVP_CTRL_GCM_SET_TAG failed.");
        goto EXIT;
    }
    if (EVP_DecryptUpdate(ctx, outData, &outBufLen, trueEncryptedData, srcDataLen - AES_GCM_TAG_LEN) != 1) {
        COMM_LOGE(COMM_ADAPTER, "EVP_DecryptUpdate failed.");
        goto EXIT;
    }
    outLen += outBufLen;
    if (EVP_DecryptFinal_ex(ctx, outData + outBufLen, &outBufLen) != 1) {
        COMM_LOGE(COMM_ADAPTER, "EVP_DecryptFinal_ex failed.");
        goto EXIT;
    }
    if (outBufLen > INT32_MAX - outLen) {
        COMM_LOGE(COMM_ADAPTER, "outLen convert overflow.");
        goto EXIT;
    }
    outLen += outBufLen;
    *outDataLen = outLen;
    EVP_CIPHER_CTX_free(ctx);
    return SOFTBUS_OK;
EXIT:
    EVP_CIPHER_CTX_free(ctx);
    return SOFTBUS_DECRYPT_ERR;
}

int32_t SoftBusAesGcmEncrypt(
    const AesInputData *inData, AesCipherKey *cipherKey, int32_t encMode, AesOutputData *outData)
{
    if (inData == NULL || inData->data == NULL || cipherKey == NULL || cipherKey->key == NULL ||
        cipherKey->iv == NULL || outData == NULL || (encMode != ENCRYPT_MODE && encMode != DECRYPT_MODE)) {
        COMM_LOGE(COMM_ADAPTER, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t encryptDataLen = inData->len + AES_GCM_TAG_LEN;
    uint8_t *encryptData = (uint8_t *)SoftBusCalloc(encryptDataLen);
    if (encryptData == NULL) {
        COMM_LOGE(COMM_ADAPTER, "encrypt data calloc fail.");
        return SOFTBUS_MALLOC_ERR;
    }
    if (encMode == ENCRYPT_MODE) {
        if (OpensslAesGcmEncrypt(inData->data, inData->len, cipherKey, encryptData, &encryptDataLen) != SOFTBUS_OK) {
            COMM_LOGE(COMM_ADAPTER, "OpensslAesGcmEncrypt failed.");
            SoftBusFree(encryptData);
            encryptData = NULL;
            return SOFTBUS_ENCRYPT_ERR;
        }
    } else {
        if (OpensslAesGcmDecrypt(inData->data, inData->len, cipherKey, encryptData, &encryptDataLen) != SOFTBUS_OK) {
            COMM_LOGE(COMM_ADAPTER, "OpensslAesGcmDecrypt failed.");
            SoftBusFree(encryptData);
            encryptData = NULL;
            return SOFTBUS_DECRYPT_ERR;
        }
    }
    outData->data = encryptData;
    outData->len = encryptDataLen;
    return SOFTBUS_OK;
}