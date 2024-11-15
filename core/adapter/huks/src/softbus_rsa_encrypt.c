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

#include "softbus_rsa_encrypt.h"

#include <hks_api.h>
#include <hks_param.h>
#include <hks_type.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <securec.h>

#include "comm_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

static const uint8_t SOFTBUS_RSA_KEY_ALIAS[] = "DsoftbusRsaKey";
static const struct HksBlob g_rsaKeyAlias = { sizeof(SOFTBUS_RSA_KEY_ALIAS), (uint8_t *)SOFTBUS_RSA_KEY_ALIAS };
static int32_t ConstructKeyParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramCount);
static struct HksParam g_generateParams[] = {
    { .tag = HKS_TAG_ALGORITHM,          .uint32Param = HKS_ALG_RSA                                      },
    { .tag = HKS_TAG_KEY_SIZE,           .uint32Param = HKS_RSA_KEY_SIZE_2048                            },
    { .tag = HKS_TAG_PURPOSE,            .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    { .tag = HKS_TAG_DIGEST,             .uint32Param = HKS_DIGEST_SHA256                                },
    { .tag = HKS_TAG_PADDING,            .uint32Param = HKS_PADDING_OAEP                                 },
    { .tag = HKS_TAG_BLOCK_MODE,         .uint32Param = HKS_MODE_ECB                                     },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE                        },
};
static struct HksParam g_decryptParams[] = {
    { .tag = HKS_TAG_ALGORITHM,          .uint32Param = HKS_ALG_RSA              },
    { .tag = HKS_TAG_PURPOSE,            .uint32Param = HKS_KEY_PURPOSE_DECRYPT  },
    { .tag = HKS_TAG_KEY_SIZE,           .uint32Param = HKS_RSA_KEY_SIZE_2048    },
    { .tag = HKS_TAG_PADDING,            .uint32Param = HKS_PADDING_OAEP         },
    { .tag = HKS_TAG_DIGEST,             .uint32Param = HKS_DIGEST_SHA256        },
    { .tag = HKS_TAG_BLOCK_MODE,         .uint32Param = HKS_MODE_ECB             },
    { .tag = HKS_TAG_MGF_DIGEST,         .uint32Param = HKS_DIGEST_SHA1          },
    { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
};

static bool IsRsaKeyPairExist(struct HksBlob Alias)
{
    struct HksParamSet *paramSet = NULL;
    struct HksParam keyExistparams[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    if (ConstructKeyParamSet(&paramSet, keyExistparams, sizeof(keyExistparams) / sizeof(struct HksParam)) !=
        SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "rsa keypair ConstructKeyParamSet failed.");
        return false;
    }
    if (HksKeyExist(&Alias, paramSet) == HKS_SUCCESS) {
        COMM_LOGI(COMM_UTILS, "rsa keypair already exist.");
        HksFreeParamSet(&paramSet);
        return true;
    } else {
        COMM_LOGE(COMM_UTILS, "rsa keypair do not exist.");
        HksFreeParamSet(&paramSet);
        return false;
    }
}

static int32_t ConstructKeyParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramCount)
{
    if (HksInitParamSet(paramSet) != HKS_SUCCESS) {
        COMM_LOGE(COMM_UTILS, "HksInitParamSet failed.");
        return SOFTBUS_HUKS_ERR;
    }
    if (HksAddParams(*paramSet, params, paramCount) != HKS_SUCCESS) {
        COMM_LOGE(COMM_UTILS, "HksAddParams failed.");
        HksFreeParamSet(paramSet);
        *paramSet = NULL;
        return SOFTBUS_HUKS_ERR;
    }
    if (HksBuildParamSet(paramSet) != HKS_SUCCESS) {
        COMM_LOGE(COMM_UTILS, "HksBuildParamSet failed.");
        HksFreeParamSet(paramSet);
        *paramSet = NULL;
        return SOFTBUS_HUKS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GenerateRsaKeyPair(void)
{
    struct HksParamSet *paramSet = NULL;
    if (ConstructKeyParamSet(&paramSet, g_generateParams, sizeof(g_generateParams) / sizeof(struct HksParam)) !=
        SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "ConstructKeyParamSet failed.");
        return SOFTBUS_HUKS_ERR;
    }
    if (HksGenerateKey(&g_rsaKeyAlias, paramSet, NULL) != HKS_SUCCESS) {
        COMM_LOGE(COMM_UTILS, "HksGenerateKey failed.");
        HksFreeParamSet(&paramSet);
        paramSet = NULL;
        return SOFTBUS_HUKS_ERR;
    }
    HksFreeParamSet(&paramSet);
    paramSet = NULL;
    return SOFTBUS_OK;
}

int32_t SoftBusGetPublicKey(uint8_t *publicKey, uint32_t publicKeyLen)
{
    if (publicKey == NULL || publicKeyLen == 0) {
        COMM_LOGE(COMM_UTILS, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!IsRsaKeyPairExist(g_rsaKeyAlias)) {
        if (GenerateRsaKeyPair() != SOFTBUS_OK) {
            COMM_LOGE(COMM_UTILS, "Generate RsaKeyPair failed");
            return SOFTBUS_HUKS_ERR;
        }
    }
    // Export public key
    uint8_t pubKey[HKS_RSA_KEY_SIZE_4096] = { 0 };
    struct HksBlob publicKeyBlob = { HKS_RSA_KEY_SIZE_4096, pubKey };
    struct HksParamSet *paramSet = NULL;
    struct HksParam publicKeyParams[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    if (ConstructKeyParamSet(&paramSet, publicKeyParams, sizeof(publicKeyParams) / sizeof(struct HksParam)) !=
        SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "public key ConstructKeyParamSet failed.");
        return SOFTBUS_HUKS_ERR;
    }
    if (HksExportPublicKey(&g_rsaKeyAlias, paramSet, &publicKeyBlob) != HKS_SUCCESS) {
        COMM_LOGE(COMM_UTILS, "HksExportPubKey failed.");
        HksFreeParamSet(&paramSet);
        return SOFTBUS_HUKS_ERR;
    }
    HksFreeParamSet(&paramSet);
    COMM_LOGD(COMM_UTILS, "public key is X509, size=%{public}u.", publicKeyBlob.size);
    if (memcpy_s(publicKey, publicKeyLen, publicKeyBlob.data, publicKeyBlob.size) != EOK) {
        COMM_LOGE(COMM_UTILS, "publicKey memcpy_s failed.");
        (void)memset_s(pubKey, sizeof(pubKey), 0, sizeof(pubKey));
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(pubKey, sizeof(pubKey), 0, sizeof(pubKey));
    return SOFTBUS_OK;
}

static BN_CTX *GetRsaBigNum(const BIGNUM *modNum, BIGNUM **base, BIGNUM **result, uint8_t **buf, int32_t *bufNum)
{
    if (modNum == NULL || base == NULL || result == NULL || buf == NULL || bufNum == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param.");
        return NULL;
    }
    BN_CTX *ctx = BN_CTX_new();
    if (ctx == NULL) {
        return NULL;
    }
    BN_CTX_start(ctx);
    *base = BN_CTX_get(ctx);
    *result = BN_CTX_get(ctx);
    if (*base == NULL || *result == NULL) {
        COMM_LOGE(COMM_UTILS, "BN_CTX_get failed.");
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return NULL;
    }
    *bufNum = BN_num_bytes(modNum);
    if (*bufNum == 0) {
        COMM_LOGE(COMM_UTILS, "BN_num_bytes failed.");
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        return NULL;
    }
    if (*buf != NULL) {
        OPENSSL_clear_free(*buf, *bufNum);
        *buf = NULL;
    }
    *buf = OPENSSL_malloc(*bufNum);
    if (*buf == NULL) {
        COMM_LOGE(COMM_UTILS, "OPENSSL_malloc failed.");
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
        OPENSSL_clear_free(*buf, *bufNum);
        *buf = NULL;
        return NULL;
    }
    return ctx;
}

static int32_t EncryptByPublicKey(const uint8_t *src, uint32_t srcLen, const RSA *rsa, uint8_t *out, uint32_t outLen)
{
    if (src == NULL || srcLen == 0 || rsa == NULL || out == NULL || outLen < SOFTBUS_RSA_ENCRYPT_LEN) {
        COMM_LOGE(COMM_UTILS, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = SOFTBUS_ENCRYPT_ERR;
    uint8_t *buf = NULL;
    int32_t bufNum = 0;
    BIGNUM *base = NULL;
    BIGNUM *result = NULL;
    BN_CTX *ctx = NULL;

    const BIGNUM *modNum = RSA_get0_n(rsa);
    const BIGNUM *exp = RSA_get0_e(rsa);
    if ((BN_num_bits(modNum) > OPENSSL_RSA_MAX_MODULUS_BITS) || (BN_ucmp(modNum, exp) <= 0) ||
        ((BN_num_bits(modNum) > OPENSSL_RSA_SMALL_MODULUS_BITS) && (BN_num_bits(exp) > OPENSSL_RSA_MAX_PUBEXP_BITS))) {
        COMM_LOGE(COMM_UTILS, "invalid param rsa.");
        return SOFTBUS_INVALID_PARAM;
    }
    do {
        ctx = GetRsaBigNum(modNum, &base, &result, &buf, &bufNum);
        if (ctx == NULL) {
            COMM_LOGE(COMM_UTILS, "GetRsaBigNum failed.");
            break;
        }
        const EVP_MD *md = EVP_sha256();
        const EVP_MD *mgf1md = EVP_sha1();
        ret = RSA_padding_add_PKCS1_OAEP_mgf1(buf, bufNum, src, srcLen, NULL, 0, md, mgf1md);
        if (ret <= 0 || BN_bin2bn(buf, bufNum, base) == NULL || BN_ucmp(base, modNum) >= 0) {
            COMM_LOGE(COMM_UTILS, "RSA_padding_add_PKCS1_OAEP_mgf1 failed or invalid BIGNUM param .");
            break;
        }
        BN_mod_exp_mont(result, base, exp, modNum, ctx, NULL);
        ret = BN_bn2binpad(result, out, bufNum);
        if (ret < 0) {
            COMM_LOGE(COMM_UTILS, "BN_bn2binpad failed.");
            break;
        }
        ret = SOFTBUS_OK;
    } while (0);
    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    OPENSSL_clear_free(buf, bufNum);
    buf = NULL;
    return ret;
}

static int32_t DataToPublicKey(const uint8_t *bufKey, int32_t bufKeyLen, RSA **pubKey)
{
    int32_t res;
    BIO *pBio = NULL;

    if (bufKey == NULL || bufKeyLen < 0 || pubKey == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    pBio = BIO_new(BIO_s_mem());
    if (pBio == NULL) {
        COMM_LOGE(COMM_UTILS, "Bio data malloc failed.");
        return SOFTBUS_BIO_ERR;
    }
    res = BIO_write(pBio, bufKey, bufKeyLen);
    if (res <= 0) {
        COMM_LOGE(COMM_UTILS, "Bio data write failed.");
        BIO_free(pBio);
        return SOFTBUS_BIO_ERR;
    }
    *pubKey = d2i_RSA_PUBKEY_bio(pBio, NULL);
    if (*pubKey == NULL) {
        COMM_LOGE(COMM_UTILS, "Data transfer public key failed.");
        BIO_free(pBio);
        return SOFTBUS_BIO_ERR;
    }
    BIO_free(pBio);
    return SOFTBUS_OK;
}

int32_t SoftBusRsaEncrypt(const uint8_t *srcData, uint32_t srcDataLen, PublicKey *publicKey, uint8_t **encryptedData,
    uint32_t *encryptedDataLen)
{
    if (srcData == NULL || srcDataLen == 0 || publicKey == NULL || publicKey->key == NULL ||
        publicKey->len <= RSA_PUB_KEY_LEN_SUBTRACT_ENCRYPT_LEN || encryptedData == NULL || encryptedDataLen == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    RSA *peerPubKey = NULL;
    if (DataToPublicKey(publicKey->key, publicKey->len, &peerPubKey) != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "DataToPublicKey failed.");
        return SOFTBUS_BIO_ERR;
    }
    uint32_t cipherTextLen = publicKey->len - RSA_PUB_KEY_LEN_SUBTRACT_ENCRYPT_LEN;
    uint8_t *cipherText = (uint8_t *)SoftBusCalloc(cipherTextLen);
    if (cipherText == NULL) {
        COMM_LOGE(COMM_UTILS, "cipherText calloc failed.");
        RSA_free(peerPubKey);
        return SOFTBUS_MALLOC_ERR;
    }
    if (EncryptByPublicKey(srcData, srcDataLen, peerPubKey, cipherText, cipherTextLen) != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "EncryptByPublicKey failed.");
        RSA_free(peerPubKey);
        SoftBusFree(cipherText);
        return SOFTBUS_ENCRYPT_ERR;
    }
    *encryptedDataLen = cipherTextLen;
    *encryptedData = (uint8_t *)SoftBusCalloc(cipherTextLen);
    if (*encryptedData == NULL) {
        COMM_LOGE(COMM_UTILS, "encryptedData calloc failed.");
        (void)memset_s(cipherText, cipherTextLen, 0, cipherTextLen);
        RSA_free(peerPubKey);
        SoftBusFree(cipherText);
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(*encryptedData, cipherTextLen, cipherText, cipherTextLen) != EOK) {
        COMM_LOGE(COMM_UTILS, "encryptedData memcpy_s failed.");
        (void)memset_s(cipherText, cipherTextLen, 0, cipherTextLen);
        RSA_free(peerPubKey);
        SoftBusFree(cipherText);
        SoftBusFree(*encryptedData);
        *encryptedData = NULL;
        return SOFTBUS_MEM_ERR;
    }
    RSA_free(peerPubKey);
    SoftBusFree(cipherText);
    return SOFTBUS_OK;
}

int32_t SoftBusRsaDecrypt(
    const uint8_t *srcData, uint32_t srcDataLen, uint8_t **decryptedData, uint32_t *decryptedDataLen)
{
    if (srcData == NULL || srcDataLen == 0 || decryptedData == NULL || decryptedDataLen == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    struct HksBlob encryptedBlob = { srcDataLen, (uint8_t *)srcData };
    struct HksParamSet *paramSet = NULL;
    if (ConstructKeyParamSet(&paramSet, g_decryptParams, sizeof(g_decryptParams) / sizeof(struct HksParam)) !=
        SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "ConstructKeyParamSet failed.");
        return SOFTBUS_HUKS_ERR;
    }
    struct HksBlob decryptedBlob = { .size = HKS_RSA_KEY_SIZE_4096,
        .data = (uint8_t *)(SoftBusCalloc(HKS_RSA_KEY_SIZE_4096)) };
    if (decryptedBlob.data == NULL) {
        COMM_LOGE(COMM_UTILS, "decryptedBlob.data calloc failed.");
        HksFreeParamSet(&paramSet);
        return SOFTBUS_MALLOC_ERR;
    }
    if (HksDecrypt(&g_rsaKeyAlias, paramSet, &encryptedBlob, &decryptedBlob) != HKS_SUCCESS) {
        COMM_LOGE(COMM_UTILS, "HksDecrypt failed.");
        HksFreeParamSet(&paramSet);
        SoftBusFree(decryptedBlob.data);
        return SOFTBUS_DECRYPT_ERR;
    }
    COMM_LOGD(COMM_UTILS, "HksDecrypt success.");
    *decryptedDataLen = decryptedBlob.size;
    *decryptedData = (uint8_t *)SoftBusCalloc(decryptedBlob.size);
    if (*decryptedData == NULL) {
        COMM_LOGE(COMM_UTILS, "decryptedData calloc failed");
        (void)memset_s(decryptedBlob.data, decryptedBlob.size, 0, decryptedBlob.size);
        HksFreeParamSet(&paramSet);
        SoftBusFree(decryptedBlob.data);
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(*decryptedData, decryptedBlob.size, decryptedBlob.data, decryptedBlob.size) != EOK) {
        COMM_LOGE(COMM_UTILS, "decryptedData memcpy_s failed");
        (void)memset_s(decryptedBlob.data, decryptedBlob.size, 0, decryptedBlob.size);
        HksFreeParamSet(&paramSet);
        SoftBusFree(decryptedBlob.data);
        SoftBusFree(*decryptedData);
        *decryptedData = NULL;
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(decryptedBlob.data, decryptedBlob.size, 0, decryptedBlob.size);
    HksFreeParamSet(&paramSet);
    SoftBusFree(decryptedBlob.data);
    return SOFTBUS_OK;
}

