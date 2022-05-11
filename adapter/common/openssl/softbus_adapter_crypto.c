/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "softbus_adapter_file.h"
#include "softbus_adapter_log.h"
#include "softbus_errcode.h"

static pthread_mutex_t g_randomLock = PTHREAD_MUTEX_INITIALIZER;

#define OPENSSL_EVP_PADDING_FUNC_OPEN (1)
#define OPENSSL_EVP_PADDING_FUNC_CLOSE (0)

#define EVP_AES_128_GCM_KEYLEN 16
#define EVP_AES_256_GCM_KEYLEN 32

static EVP_CIPHER *GetSslAlgorithmByKeyLen(uint32_t keyLen)
{
    switch (keyLen) {
        case EVP_AES_128_GCM_KEYLEN:
            return (EVP_CIPHER *)EVP_aes_128_gcm();
        case EVP_AES_256_GCM_KEYLEN:
            return (EVP_CIPHER *)EVP_aes_256_gcm();
    }
    return NULL;
}

static int32_t OpensslEvpInit(EVP_CIPHER_CTX **ctx, const AesGcmCipherKey *cipherkey, bool mode)
{
    EVP_CIPHER *cipher = GetSslAlgorithmByKeyLen(cipherkey->keyLen);
    if (cipher == NULL) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "get cipher fail.");
        return SOFTBUS_DECRYPT_ERR;
    }
    int32_t ret;
    *ctx = EVP_CIPHER_CTX_new();
    if (*ctx == NULL) {
        return SOFTBUS_DECRYPT_ERR;
    }
    EVP_CIPHER_CTX_set_padding(*ctx, OPENSSL_EVP_PADDING_FUNC_OPEN);
    if (mode == true) {
        ret = EVP_EncryptInit_ex(*ctx, cipher, NULL, NULL, NULL);
        if (ret != 1) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_EncryptInit_ex fail.");
            EVP_CIPHER_CTX_free(*ctx);
            return SOFTBUS_DECRYPT_ERR;
        }
    } else {
        ret = EVP_DecryptInit_ex(*ctx, cipher, NULL, NULL, NULL);
        if (ret != 1) {
            HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_DecryptInit_ex fail.");
            EVP_CIPHER_CTX_free(*ctx);
            return SOFTBUS_DECRYPT_ERR;
        }
    }
    ret = EVP_CIPHER_CTX_ctrl(*ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, NULL);
    if (ret != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "Set iv len fail.");
        EVP_CIPHER_CTX_free(*ctx);
        return SOFTBUS_DECRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t PackIvAndTag(EVP_CIPHER_CTX *ctx, const AesGcmCipherKey *cipherkey,
    uint32_t dataLen, unsigned char *cipherText, uint32_t cipherTextLen)
{
    if ((dataLen + OVERHEAD_LEN) > cipherTextLen) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "Encrypt invalid para.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    if (memcpy_s(cipherText, cipherTextLen - dataLen, cipherkey->iv, GCM_IV_LEN) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP memcpy iv fail.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    char tagbuf[TAG_LEN];
    int ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, (void *)tagbuf);
    if (ret != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_CIPHER_CTX_ctrl fail.");
        return SOFTBUS_DECRYPT_ERR;
    }
    if (memcpy_s(cipherText + dataLen + GCM_IV_LEN,
        cipherTextLen - dataLen - GCM_IV_LEN, tagbuf, TAG_LEN) != EOK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP memcpy tag fail.");
        return SOFTBUS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t SslAesGcmEncrypt(const AesGcmCipherKey *cipherkey, const unsigned char *plainText,
    uint32_t plainTextSize, unsigned char *cipherText, uint32_t cipherTextLen)
{
    if ((cipherkey == NULL) || (plainText == NULL) || (plainTextSize == 0) || cipherText == NULL ||
        (cipherTextLen < plainTextSize + OVERHEAD_LEN)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "Encrypt invalid para.");
        return SOFTBUS_INVALID_PARAM;
    }
    
    int32_t outlen = 0;
    int32_t outbufLen;
    EVP_CIPHER_CTX *ctx = NULL;
    int32_t ret = OpensslEvpInit(&ctx, cipherkey, true);
    if (ret != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "OpensslEvpInit fail.");
        return SOFTBUS_DECRYPT_ERR;
    }
    ret = EVP_EncryptInit_ex(ctx, NULL, NULL, cipherkey->key, cipherkey->iv);
    if (ret != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_EncryptInit_ex fail.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_DECRYPT_ERR;
    }
    ret = EVP_EncryptUpdate(ctx, cipherText + GCM_IV_LEN,
        (int32_t *)&outbufLen, plainText, plainTextSize);
    if (ret != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_EncryptUpdate fail.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_DECRYPT_ERR;
    }
    outlen += outbufLen;
    ret = EVP_EncryptFinal_ex(ctx, cipherText + GCM_IV_LEN + outbufLen, (int32_t *)&outbufLen);
    if (ret != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_EncryptFinal_ex fail.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_DECRYPT_ERR;
    }
    outlen += outbufLen;
    ret = PackIvAndTag(ctx, cipherkey, outlen, cipherText, cipherTextLen);
    if (ret != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "pack iv and tag fail.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_DECRYPT_ERR;
    }
    EVP_CIPHER_CTX_free(ctx);
    return (outlen + OVERHEAD_LEN);
}

static int32_t SslAesGcmDecrypt(const AesGcmCipherKey *cipherkey, const unsigned char *cipherText,
    uint32_t cipherTextSize, unsigned char *plain, uint32_t plainLen)
{
    if ((cipherkey == NULL) || (cipherText == NULL) || (cipherTextSize <= OVERHEAD_LEN) || plain == NULL ||
        (plainLen < cipherTextSize - OVERHEAD_LEN)) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "Decrypt invalid para.");
        return SOFTBUS_INVALID_PARAM;
    }

    int32_t outlen = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int32_t ret = OpensslEvpInit(&ctx, cipherkey, false);
    if (ret != SOFTBUS_OK) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "OpensslEvpInit fail.");
        return SOFTBUS_DECRYPT_ERR;
    }
    ret = EVP_DecryptInit_ex(ctx, NULL, NULL, cipherkey->key, cipherkey->iv);
    if (ret != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_EncryptInit_ex fail.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_DECRYPT_ERR;
    }
    ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
        (void *)(cipherText + (cipherTextSize - TAG_LEN)));
    if (ret != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_DecryptUpdate fail.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_DECRYPT_ERR;
    }
    ret = EVP_DecryptUpdate(ctx, plain, (int32_t *)&plainLen,
        cipherText + GCM_IV_LEN, cipherTextSize - OVERHEAD_LEN);
    if (ret != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_DecryptUpdate fail.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_DECRYPT_ERR;
    }
    outlen += plainLen;
    ret = EVP_DecryptFinal_ex(ctx, plain + plainLen, (int32_t *)&plainLen);
    if (ret != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "EVP_DecryptFinal_ex fail.");
        EVP_CIPHER_CTX_free(ctx);
        return SOFTBUS_DECRYPT_ERR;
    }
    outlen += plainLen;
    EVP_CIPHER_CTX_free(ctx);
    return outlen;
}

int32_t SoftBusBase64Encode(unsigned char *dst, size_t dlen,
    size_t *olen, const unsigned char *src, size_t slen)
{
    if (dst == NULL || dlen == 0 || olen == NULL || src == NULL || slen == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    *olen = 0;
    int32_t outlen;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    if (ctx == NULL) {
        return SOFTBUS_DECRYPT_ERR;
    }
    EVP_EncodeInit(ctx);
    int32_t ret = EVP_EncodeUpdate(ctx, dst, &outlen, src, slen);
    if (ret != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "[TRANS] EVP_EncodeUpdate fail.");
        EVP_ENCODE_CTX_free(ctx);
        return SOFTBUS_DECRYPT_ERR;
    }
    *olen += outlen;
    EVP_EncodeFinal(ctx, dst + outlen, &outlen);
    *olen += outlen;
    if ((*olen > 0) && (dst[*olen - 1] == '\n')) {
        (*olen)--;
        dst[*olen] = 0;
    }
    EVP_ENCODE_CTX_free(ctx);
    return SOFTBUS_OK;
}

int32_t SoftBusBase64Decode(unsigned char *dst, size_t dlen,
    size_t *olen, const unsigned char *src, size_t slen)
{
    if (dst == NULL || dlen == 0 || olen == NULL || src == NULL || slen == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    *olen = 0;
    int32_t outlen;
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    if (ctx == NULL) {
        return SOFTBUS_DECRYPT_ERR;
    }
    EVP_DecodeInit(ctx);
    int32_t ret = EVP_DecodeUpdate(ctx, dst, &outlen, src, slen);
    if (ret == -1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "[TRANS] EVP_DecodeUpdate fail.");
        EVP_ENCODE_CTX_free(ctx);
        return SOFTBUS_DECRYPT_ERR;
    }
    *olen += outlen;
    ret = EVP_DecodeFinal(ctx, dst + outlen, &outlen);
    if (ret != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "[TRANS] EVP_DecodeFinal fail.");
        EVP_ENCODE_CTX_free(ctx);
        return SOFTBUS_DECRYPT_ERR;
    }
    *olen += outlen;
    EVP_ENCODE_CTX_free(ctx);
    return SOFTBUS_OK;
}

int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash)
{
    if (str == NULL || hash == NULL || len == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t olen;
    int32_t ret = EVP_Digest(str, len, hash, &olen, EVP_sha256(), NULL);
    if (ret != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "[TRANS] Get Openssl Hash fail.");
        return SOFTBUS_DECRYPT_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len)
{
    if (randStr == NULL || len == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    static bool initFlag = false;
    int32_t ret;

    if (pthread_mutex_lock(&g_randomLock) != 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "lock mutex failed.");
        return SOFTBUS_ERR;
    }

    if (initFlag == false) {
        RAND_seed(randStr, (int32_t)len);
        initFlag = true;
    }

    ret = RAND_bytes(randStr, (int32_t)len);
    pthread_mutex_unlock(&g_randomLock);
    if (ret != 1) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "gen random error, ret[%d]", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusGenerateSessionKey(char *key, uint32_t len)
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
    int32_t result = SslAesGcmEncrypt(cipherKey, input, inLen, encryptData, outLen);
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
    int32_t result = SslAesGcmEncrypt(cipherKey, input, inLen, encryptData, outLen);
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
    int32_t result = SslAesGcmDecrypt(cipherKey, input, inLen, decryptData, outLen);
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
        HILOG_ERROR(SOFTBUS_HILOG_ID, "CryptoRand open file fail");
        return 0;
    }
    uint32_t value = 0;
    int32_t len = SoftBusReadFile(fd, &value, sizeof(uint32_t));
    if (len < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "CryptoRand read file fail");
        return 0;
    }
    SoftBusCloseFile(fd);
    return value;
}
