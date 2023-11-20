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

#include "softbus_rsa_encrypt.h"

#include <hks_api.h>
#include <hks_param.h>
#include <hks_type.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <securec.h>
 
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log_old.h"

static const uint8_t SOFTBUS_RSA_KEY_ALIAS[] = "DsoftbusRsaKey";
static const struct HksBlob g_rsaKeyAlias = { sizeof(SOFTBUS_RSA_KEY_ALIAS), (uint8_t *)SOFTBUS_RSA_KEY_ALIAS };
static struct HksParam g_generateParams[] = {
    { .tag = HKS_TAG_ALGORITHM,  .uint32Param = HKS_ALG_RSA                                      },
    { .tag = HKS_TAG_KEY_SIZE,   .uint32Param = HKS_RSA_KEY_SIZE_2048                            },
    { .tag = HKS_TAG_PURPOSE,    .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT},
    { .tag = HKS_TAG_DIGEST,     .uint32Param = HKS_DIGEST_SHA256                                },
    { .tag = HKS_TAG_PADDING,    .uint32Param = HKS_PADDING_OAEP                                 },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB                                     },
};
static struct HksParam g_decryptParams[] = {
    { .tag = HKS_TAG_ALGORITHM,  .uint32Param = HKS_ALG_RSA            },
    { .tag = HKS_TAG_PURPOSE,    .uint32Param = HKS_KEY_PURPOSE_DECRYPT},
    { .tag = HKS_TAG_KEY_SIZE,   .uint32Param = HKS_RSA_KEY_SIZE_2048  },
    { .tag = HKS_TAG_PADDING,    .uint32Param = HKS_PADDING_OAEP       },
    { .tag = HKS_TAG_DIGEST,     .uint32Param = HKS_DIGEST_SHA256      },
    { .tag = HKS_TAG_BLOCK_MODE, .uint32Param = HKS_MODE_ECB           },
};

static bool IsRsaKeyPairExist(struct HksBlob Alias)
{
    if (HksKeyExist(&Alias, NULL) == HKS_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "rsa keypair already exist.");
        return true;
    } else {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "rsa keypair do not exist.");
        return false;
    }
}

static int32_t ConstructKeyParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramCount)
{
    if (HksInitParamSet(paramSet) != HKS_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "HksInitParamSet failed.");
        return SOFTBUS_ERR;
    }
    if (HksAddParams(*paramSet, params, paramCount) != HKS_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "HksAddParams failed.");
        HksFreeParamSet(paramSet);
        return SOFTBUS_ERR;
    }
    if (HksBuildParamSet(paramSet) != HKS_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "HksBuildParamSet failed.");
        HksFreeParamSet(paramSet);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GenerateRsaKeyPair(void)
{
    struct HksParamSet *paramSet = NULL;
    if (ConstructKeyParamSet(&paramSet, g_generateParams, sizeof(g_generateParams) / sizeof(struct HksParam)) !=
        SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    if (HksGenerateKey(&g_rsaKeyAlias, paramSet, NULL) != HKS_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "HksGenerateKey failed.");
        HksFreeParamSet(&paramSet);
        return SOFTBUS_ERR;
    }
    HksFreeParamSet(&paramSet);
    return SOFTBUS_OK;
}

int32_t SoftbusGetPublicKey(uint8_t *publicKey, uint32_t publicKeyLen)
{
    if (publicKey == NULL || publicKeyLen == 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (!IsRsaKeyPairExist(g_rsaKeyAlias)) {
        if (GenerateRsaKeyPair() != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "Generate RsaKeyPair failed");
            return SOFTBUS_ERR;
        }
    }
    // Export public key
    uint8_t pubKey[HKS_RSA_KEY_SIZE_4096] = { 0 };
    struct HksBlob publicKeyBlob = { HKS_RSA_KEY_SIZE_4096, pubKey };
    if (HksExportPublicKey(&g_rsaKeyAlias, NULL, &publicKeyBlob) != HKS_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "HksExportPubKey failed.");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_DBG, "X509 public key size is: %u.", publicKeyBlob.size);
    if (memcpy_s(publicKey, publicKeyBlob.size, publicKeyBlob.data, publicKeyBlob.size) != EOK) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t X509ToRsaPublicKey(struct HksBlob *x509Key, struct HksBlob *publicKey)
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_DBG, "X509ToRsaPublicKey invoked.");
    uint8_t *data = x509Key->data;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, (const unsigned char **)&data, x509Key->size);
    if (pkey == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "d2i_PUBKEY failed.");
        return SOFTBUS_ERR;
    }
    const RSA *rsa = EVP_PKEY_get0_RSA(pkey);
    if (rsa == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "EVP_PKEY_get0_RSA failed.");
        return SOFTBUS_ERR;
    }
    int32_t nSizeTemp = BN_num_bytes(RSA_get0_n(rsa));
    int32_t eSizeTemp = BN_num_bytes(RSA_get0_e(rsa));
    if ((nSizeTemp <= 0) || (eSizeTemp <= 0)) {
        EVP_PKEY_free(pkey);
        return SOFTBUS_ERR;
    }
    uint32_t nSize = (uint32_t)nSizeTemp;
    uint32_t eSize = (uint32_t)eSizeTemp;
    struct HksPubKeyInfo *pubKeyInfo = (struct HksPubKeyInfo *)publicKey->data;
    pubKeyInfo->keyAlg = HKS_ALG_RSA;
    pubKeyInfo->keySize = (uint32_t)RSA_size(rsa) * BIT_NUM_OF_BYTE;
    pubKeyInfo->nOrXSize = nSize;
    pubKeyInfo->eOrYSize = eSize;
    if ((BN_bn2bin(RSA_get0_n(rsa), publicKey->data + sizeof(struct HksPubKeyInfo)) == 0) ||
        (BN_bn2bin(RSA_get0_e(rsa), publicKey->data + sizeof(struct HksPubKeyInfo) + nSize) == 0)) {
        EVP_PKEY_free(pkey);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "nSize is: %u.", nSize);
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "eSize is: %u.", eSize);
    EVP_PKEY_free(pkey);
    return SOFTBUS_OK;
}

static RSA *InitRsa(struct HksBlob *key, const bool needPrivateExponent)
{
    const struct HksKeyMaterialRsa *keyMaterial = (struct HksKeyMaterialRsa *)(key->data);
    uint8_t *buff = (uint8_t *)SoftBusCalloc(HKS_KEY_BYTES(keyMaterial->keySize));
    if (buff == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "buff calloc failed.");
        return NULL;
    }

    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    BIGNUM *d = NULL;

    uint32_t offset = sizeof(*keyMaterial);
    if (memcpy_s(buff, HKS_KEY_BYTES(keyMaterial->keySize), key->data + offset, keyMaterial->nSize) == EOK) {
        n = BN_bin2bn(buff, keyMaterial->nSize, NULL);
    }
    offset += keyMaterial->nSize;
    if (memcpy_s(buff, HKS_KEY_BYTES(keyMaterial->keySize), key->data + offset, keyMaterial->eSize) == EOK) {
        e = BN_bin2bn(buff, keyMaterial->eSize, NULL);
    }
    offset += keyMaterial->eSize;
    if (needPrivateExponent) {
        if (memcpy_s(buff, HKS_KEY_BYTES(keyMaterial->keySize), key->data + offset, keyMaterial->dSize) == EOK) {
            d = BN_bin2bn(buff, keyMaterial->dSize, NULL);
        }
    }
    RSA *rsa = RSA_new();
    if (rsa != NULL) {
        if (RSA_set0_key(rsa, n, e, d) != 1) {
            RSA_free(rsa);
            rsa = NULL;
        }
    }
    if (rsa == NULL) {
        if (n != NULL) {
            BN_free(n);
        }
        if (e != NULL) {
            BN_free(e);
        }
        if (d != NULL) {
            BN_free(d);
        }
    }
    SoftBusFree(buff);
    return rsa;
}

static const EVP_MD *GetOpensslDigestType(int digestType)
{
    switch (digestType) {
        case DIGEST_SHA256:
            return EVP_sha256();
        case DIGEST_SHA384:
            return EVP_sha384();
        case DIGEST_SHA512:
            return EVP_sha512();
        default:
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetOpensslDigestType failed.");
            return NULL;
    }
}

static int32_t EncryptByPublicKey(
    const struct HksBlob *inData, struct HksBlob *outData, struct HksBlob *key, int padding, int digestType)
{
    RSA *rsa = InitRsa(key, SOFTBUS_ERR);
    if (rsa == NULL) {
        return SOFTBUS_ERR;
    }
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        RSA_free(rsa);
        return SOFTBUS_ERR;
    }
    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return SOFTBUS_ERR;
    }
    EVP_PKEY_CTX *ectx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ectx == NULL) {
        EVP_PKEY_free(pkey);
        return SOFTBUS_ERR;
    }
    if ((EVP_PKEY_encrypt_init(ectx) != 1) || (EVP_PKEY_CTX_set_rsa_padding(ectx, padding) != 1)) {
        EVP_PKEY_CTX_free(ectx);
        EVP_PKEY_free(pkey);
        return SOFTBUS_ERR;
    }
    if (padding == RSA_PKCS1_OAEP_PADDING) {
        const EVP_MD *md = GetOpensslDigestType(digestType);
        if ((md == NULL) || (EVP_PKEY_CTX_set_rsa_oaep_md(ectx, md) != 1) ||
            (EVP_PKEY_CTX_set_rsa_mgf1_md(ectx, md) != 1)) {
            EVP_PKEY_CTX_free(ectx);
            EVP_PKEY_free(pkey);
            return SOFTBUS_ERR;
        }
    }
    size_t outLen = outData->size;
    if (EVP_PKEY_encrypt(ectx, outData->data, &outLen, inData->data, inData->size) != 1) {
        EVP_PKEY_CTX_free(ectx);
        EVP_PKEY_free(pkey);
        return SOFTBUS_ERR;
    }
    outData->size = outLen;
    EVP_PKEY_CTX_free(ectx);
    EVP_PKEY_free(pkey);
    return SOFTBUS_OK;
}

int32_t SoftbusRsaEncrypt(const uint8_t *srcData, uint32_t srcDataLen, const uint8_t *publicKey,
    uint8_t **encryptedData, uint32_t *encryptedDataLen)
{
    if (srcData == NULL || srcDataLen == 0 || publicKey == NULL || encryptedData == NULL || encryptedDataLen == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t publicKeySize = SOFTBUS_RSA_PUB_KEY_LEN;
    uint8_t huksPublicKey[publicKeySize];
    if (memcpy_s(huksPublicKey, publicKeySize, publicKey, publicKeySize) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "huksPublicKey memcpy_s failed.");
        return SOFTBUS_MEM_ERR;
    }
    struct HksBlob huksPublicKeyInfo = { publicKeySize, huksPublicKey };
    uint8_t opensslPublicKey[HKS_RSA_KEY_SIZE_4096] = { 0 };
    struct HksBlob opensslPublicKeyInfo = { HKS_RSA_KEY_SIZE_4096, opensslPublicKey };
    if (X509ToRsaPublicKey(&huksPublicKeyInfo, &opensslPublicKeyInfo) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "X509ToRsaPublicKey failed.");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_DBG, "opensslPublicKeyInfo.size is: %u.", opensslPublicKeyInfo.size);
    struct HksBlob finalPublicKeyInfo = { .size = opensslPublicKeyInfo.size,
        .data = (uint8_t *)SoftBusCalloc(opensslPublicKeyInfo.size) };
    if (finalPublicKeyInfo.data == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "malloc failed.");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(finalPublicKeyInfo.data, finalPublicKeyInfo.size, opensslPublicKeyInfo.data,
            opensslPublicKeyInfo.size) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "memcpy_s failed.");
        SoftBusFree(finalPublicKeyInfo.data);
        return SOFTBUS_ERR;
    }
    struct HksBlob plainText = { .size = srcDataLen, .data = (uint8_t *)srcData };
    struct HksBlob cipherText = { .size = HKS_RSA_KEY_SIZE_4096,
        .data = (uint8_t *)SoftBusCalloc(HKS_RSA_KEY_SIZE_4096) };
    if (cipherText.data == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "malloc failed.");
        SoftBusFree(finalPublicKeyInfo.data);
        return SOFTBUS_ERR;
    }
    if (EncryptByPublicKey(&plainText, &cipherText, &finalPublicKeyInfo, RSA_PKCS1_OAEP_PADDING, DIGEST_SHA256) !=
        SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "EVP_PKEY_encrypt failed.");
        SoftBusFree(finalPublicKeyInfo.data);
        SoftBusFree(cipherText.data);
        return SOFTBUS_ERR;
    }
    *encryptedDataLen = cipherText.size;
    *encryptedData = (uint8_t *)SoftBusCalloc(cipherText.size);
    if (*encryptedData == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "encrypted Data calloc fail");
        SoftBusFree(finalPublicKeyInfo.data);
        SoftBusFree(cipherText.data);
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(*encryptedData, cipherText.size, cipherText.data, cipherText.size) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "encryptedData memcpy_s fail");
        SoftBusFree(finalPublicKeyInfo.data);
        SoftBusFree(cipherText.data);
        return SOFTBUS_MEM_ERR;
    }
    SoftBusFree(finalPublicKeyInfo.data);
    SoftBusFree(cipherText.data);
    return SOFTBUS_OK;
}

int32_t SoftbusRsaDecrypt(const uint8_t *srcData, uint32_t srcDataLen, uint8_t **decryptedData,
    uint32_t *decryptedDataLen)
{
    if (srcData == NULL || srcDataLen == 0 || decryptedData == NULL || decryptedDataLen == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid srcData");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_DBG, "DecryptByPrivateKey invoked.");
    struct HksBlob encryptedBlob = { srcDataLen, (uint8_t *)srcData };
    struct HksParamSet *paramSet = NULL;
    if (ConstructKeyParamSet(&paramSet, g_decryptParams, sizeof(g_decryptParams) / sizeof(struct HksParam)) !=
        SOFTBUS_OK) {
        return SOFTBUS_ERR;
    }
    struct HksBlob decryptedBlob = { .size = HKS_RSA_KEY_SIZE_4096,
        .data = (uint8_t *)(SoftBusCalloc(HKS_RSA_KEY_SIZE_4096)) };
    if (decryptedBlob.data == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "decryptedBlob data calloc failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (HksDecrypt(&g_rsaKeyAlias, paramSet, &encryptedBlob, &decryptedBlob) != HKS_SUCCESS) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "HksDecrypt failed.");
        HksFreeParamSet(&paramSet);
        SoftBusFree(decryptedBlob.data);
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_DBG, "HksDecrypt success.");
    *decryptedDataLen = decryptedBlob.size;
    *decryptedData = (uint8_t *)SoftBusCalloc(decryptedBlob.size);
    if (*decryptedData == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "decrypted Data calloc fail");
        HksFreeParamSet(&paramSet);
        SoftBusFree(decryptedBlob.data);
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(*decryptedData, decryptedBlob.size, decryptedBlob.data, decryptedBlob.size) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "decrypted Data memcpy_s fail");
        HksFreeParamSet(&paramSet);
        SoftBusFree(decryptedBlob.data);
        return SOFTBUS_MEM_ERR;
    }
    HksFreeParamSet(&paramSet);
    SoftBusFree(decryptedBlob.data);
    return SOFTBUS_OK;
}