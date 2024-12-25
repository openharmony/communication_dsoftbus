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

#include "lnn_huks_utils.h"

#include <securec.h>

#include "lnn_decision_db.h"
#include "lnn_log.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define LNN_HUKS_MAX_UPDATE_RESERVED 32
#define LNN_HUKS_MAX_UPDATE_SIZE (8 * 1024)
#define LNN_HUKS_MAX_OUTDATA_SIZE (LNN_HUKS_MAX_UPDATE_SIZE + LNN_HUKS_MAX_UPDATE_RESERVED)
#define DEFAULT_ACCOUNT_ID 100

#define LNN_HUKS_IV_SIZE 16
static uint8_t g_huksIv[LNN_HUKS_IV_SIZE] = {0};
static bool g_isGenCeParams = false;
static pthread_mutex_t g_ceParamsLock = PTHREAD_MUTEX_INITIALIZER;

static struct HksParam g_genParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
        .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE
    }
};

static struct HksParam g_genCeParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT | HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_SPECIFIC_USER_ID,
        .int32Param = DEFAULT_ACCOUNT_ID
    }, {
        .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
        .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE
    }
};

static struct HksParam g_encryptParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = LNN_HUKS_IV_SIZE,
            .data = (uint8_t *)g_huksIv
        }
    }, {
        .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
        .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE
    }
};

static struct HksParam g_ceEncryptParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_ENCRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = LNN_HUKS_IV_SIZE,
            .data = (uint8_t *)g_huksIv
        }
    }, {
        .tag = HKS_TAG_SPECIFIC_USER_ID,
        .int32Param = DEFAULT_ACCOUNT_ID
    }, {
        .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
        .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE
    }
};

static struct HksParam g_decryptParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = LNN_HUKS_IV_SIZE,
            .data = (uint8_t *)g_huksIv
        }
    }, {
        .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
        .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE
    }
};

static struct HksParam g_ceDecryptParams[] = {
    {
        .tag = HKS_TAG_ALGORITHM,
        .uint32Param = HKS_ALG_AES
    }, {
        .tag = HKS_TAG_PURPOSE,
        .uint32Param = HKS_KEY_PURPOSE_DECRYPT
    }, {
        .tag = HKS_TAG_KEY_SIZE,
        .uint32Param = HKS_AES_KEY_SIZE_128
    }, {
        .tag = HKS_TAG_PADDING,
        .uint32Param = HKS_PADDING_NONE
    }, {
        .tag = HKS_TAG_BLOCK_MODE,
        .uint32Param = HKS_MODE_CBC
    }, {
        .tag = HKS_TAG_DIGEST,
        .uint32Param = HKS_DIGEST_NONE
    }, {
        .tag = HKS_TAG_IV,
        .blob = {
            .size = LNN_HUKS_IV_SIZE,
            .data = (uint8_t *)g_huksIv
        }
    }, {
        .tag = HKS_TAG_SPECIFIC_USER_ID,
        .int32Param = DEFAULT_ACCOUNT_ID
    }, {
        .tag = HKS_TAG_AUTH_STORAGE_LEVEL,
        .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE
    }
};

static struct HksParamSet *g_genParamSet = NULL;
static struct HksParamSet *g_genCeParamSet = NULL;
static struct HksParamSet *g_encryptParamSet = NULL;
static struct HksParamSet *g_ceEncryptParamSet = NULL;
static struct HksParamSet *g_decryptParamSet = NULL;
static struct HksParamSet *g_ceDecryptParamSet = NULL;

static int32_t LoopFinishByHuks(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inDataSeg, uint8_t *cur, uint32_t *outDataSize)
{
    struct HksBlob outDataFinish = {inDataSeg->size + LNN_HUKS_MAX_UPDATE_RESERVED, NULL};
    outDataFinish.data = (uint8_t *)SoftBusCalloc(outDataFinish.size);
    if (outDataFinish.data == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc outDataFinish.data fail");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = HksFinish(handle, paramSet, inDataSeg, &outDataFinish);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks finish fail, huks errcode=%{public}d", ret);
        SoftBusFree(outDataFinish.data);
        return SOFTBUS_HUKS_FINISH_ERR;
    }
    (void)memcpy_s(cur, outDataFinish.size, outDataFinish.data, outDataFinish.size);
    *outDataSize += outDataFinish.size;
    SoftBusFree(outDataFinish.data);
    return SOFTBUS_OK;
}

static int32_t UpdateLoopFinishByHuks(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inData, struct HksBlob *outData)
{
    struct HksBlob inDataSeg = *inData;
    uint8_t *lastPtr = inData->data + inData->size - 1;
    struct HksBlob outDataSeg = {LNN_HUKS_MAX_OUTDATA_SIZE, NULL};
    uint8_t *cur = outData->data;
    outData->size = 0;
    inDataSeg.size = LNN_HUKS_MAX_UPDATE_SIZE;

    while (inDataSeg.data <= lastPtr) {
        if (inDataSeg.data + LNN_HUKS_MAX_UPDATE_SIZE <= lastPtr) {
            outDataSeg.size = LNN_HUKS_MAX_OUTDATA_SIZE;
        } else {
            inDataSeg.size = lastPtr - inDataSeg.data + 1;
            break;
        }
        outDataSeg.data = (uint8_t *)SoftBusCalloc(outDataSeg.size);
        if (outDataSeg.data == NULL) {
            LNN_LOGE(LNN_LEDGER, "calloc outDataSeg.data fail");
            return SOFTBUS_MEM_ERR;
        }
        int32_t ret = HksUpdate(handle, paramSet, &inDataSeg, &outDataSeg);
        if (ret != HKS_SUCCESS) {
            LNN_LOGE(LNN_LEDGER, "huks update fail, errcode=%{public}d", ret);
            SoftBusFree(outDataSeg.data);
            return SOFTBUS_HUKS_UPDATE_ERR;
        }
        (void)memcpy_s(cur, outDataSeg.size, outDataSeg.data, outDataSeg.size);
        cur += outDataSeg.size;
        outData->size += outDataSeg.size;
        SoftBusFree(outDataSeg.data);
        inDataSeg.data += LNN_HUKS_MAX_UPDATE_SIZE;
    }
    LNN_LOGD(LNN_LEDGER, "outDataSize=%{public}d, inDataSegSize=%{public}d", outData->size, inDataSeg.size);
    return LoopFinishByHuks(handle, paramSet, &inDataSeg, cur, &outData->size);
}

static int32_t InitParamSetByHuks(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramcount)
{
    int32_t ret = HksInitParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks init param set fail, errcode=%{public}d", ret);
        return SOFTBUS_HUKS_PARAM_SET_ERR;
    }
    ret = HksAddParams(*paramSet, params, paramcount);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks add param set fail, errcode=%{public}d", ret);
        HksFreeParamSet(paramSet);
        return SOFTBUS_HUKS_PARAM_SET_ERR;
    }
    ret = HksBuildParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks build param set fail, errcode=%{public}d", ret);
        HksFreeParamSet(paramSet);
        return SOFTBUS_HUKS_PARAM_SET_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t InitCeParamSetByHuks(void)
{
    int32_t ret = InitParamSetByHuks(&g_genCeParamSet, g_genCeParams, sizeof(g_genCeParams) / sizeof(struct HksParam));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks init gen ce param set fail");
        return ret;
    }
    ret = InitParamSetByHuks(
        &g_ceEncryptParamSet, g_ceEncryptParams, sizeof(g_ceEncryptParams) / sizeof(struct HksParam));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks init ce encrypt param set fail");
        return ret;
    }
    ret = InitParamSetByHuks(
        &g_ceDecryptParamSet, g_ceDecryptParams, sizeof(g_ceDecryptParams) / sizeof(struct HksParam));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks init ce decrypt param set fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitHuksInterface(void)
{
    int32_t ret = HksInitialize();
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "initialize huks fail, errcode=%{public}d", ret);
        return SOFTBUS_HUKS_INIT_FAILED;
    }
    ret = InitParamSetByHuks(&g_genParamSet, g_genParams, sizeof(g_genParams) / sizeof(struct HksParam));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks init gen param set fail");
        return ret;
    }
    ret = InitParamSetByHuks(&g_encryptParamSet, g_encryptParams, sizeof(g_encryptParams) / sizeof(struct HksParam));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks init encrypt param set fail");
        return ret;
    }
    ret = InitParamSetByHuks(&g_decryptParamSet, g_decryptParams, sizeof(g_decryptParams) / sizeof(struct HksParam));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks init decrypt param set fail");
        return ret;
    }
    ret = InitCeParamSetByHuks();
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks init ce param set fail");
        return ret;
    }
    if (LnnCheckGenerateSoftBusKeyByHuks() != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "check generate huks key failed");
    }
    return SOFTBUS_OK;
}

static void DeinitHuksCeInterface(void)
{
    if (g_genCeParamSet != NULL) {
        HksFreeParamSet(&g_genCeParamSet);
    }
    if (g_ceEncryptParamSet != NULL) {
        HksFreeParamSet(&g_ceEncryptParamSet);
    }
    if (g_ceDecryptParamSet != NULL) {
        HksFreeParamSet(&g_ceDecryptParamSet);
    }
}

void LnnDeinitHuksInterface(void)
{
    if (g_genParamSet != NULL) {
        HksFreeParamSet(&g_genParamSet);
    }
    if (g_encryptParamSet != NULL) {
        HksFreeParamSet(&g_encryptParamSet);
    }
    if (g_decryptParamSet != NULL) {
        HksFreeParamSet(&g_decryptParamSet);
    }
    DeinitHuksCeInterface();
}

static int32_t ConstructKeyParamSet(struct HksParamSet **paramSet, const struct HksParam *params, uint32_t paramCount)
{
    if (HksInitParamSet(paramSet) != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "HksInitParamSet failed.");
        return SOFTBUS_HUKS_PARAM_SET_ERR;
    }
    if (HksAddParams(*paramSet, params, paramCount) != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "HksAddParams failed.");
        HksFreeParamSet(paramSet);
        *paramSet = NULL;
        return SOFTBUS_HUKS_PARAM_SET_ERR;
    }
    if (HksBuildParamSet(paramSet) != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "HksBuildParamSet failed.");
        HksFreeParamSet(paramSet);
        *paramSet = NULL;
        return SOFTBUS_HUKS_PARAM_SET_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t GenerateCeKeyByHuks(struct HksBlob *keyAlias)
{
    struct HksParamSet *paramSet = NULL;
    struct HksParam keyExistparams[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = DEFAULT_ACCOUNT_ID},
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE},
    };
    int32_t ret = ConstructKeyParamSet(&paramSet, keyExistparams, sizeof(keyExistparams) / sizeof(struct HksParam));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate ce key ConstructKeyParamSet failed.");
        return ret;
    }
    if (HksKeyExist(keyAlias, paramSet) == HKS_SUCCESS) {
        LNN_LOGI(LNN_LEDGER, "huks ce key has generated");
        HksFreeParamSet(&paramSet);
        return SOFTBUS_OK;
    }
    HksFreeParamSet(&paramSet);
    ret = HksGenerateKey(keyAlias, g_genCeParamSet, NULL);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks generate ce key fail, errcode=%{public}d", ret);
        return SOFTBUS_HUKS_GENERATE_KEY_ERR;
    }
    LNN_LOGI(LNN_LEDGER, "huks generate new ce key");
    return SOFTBUS_OK;
}

static int32_t GenerateDeKeyByHuks(struct HksBlob *keyAlias)
{
    struct HksParamSet *paramSet = NULL;
    struct HksParam keyExistparams[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    int32_t ret = ConstructKeyParamSet(&paramSet, keyExistparams, sizeof(keyExistparams) / sizeof(struct HksParam));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate de key ConstructKeyParamSet failed.");
        return ret;
    }
    if (HksKeyExist(keyAlias, paramSet) == HKS_SUCCESS) {
        LNN_LOGI(LNN_LEDGER, "huks de key has generated");
        HksFreeParamSet(&paramSet);
        return SOFTBUS_OK;
    }
    HksFreeParamSet(&paramSet);
    ret = HksGenerateKey(keyAlias, g_genParamSet, NULL);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks generate de key fail, errcode=%{public}d", ret);
        return SOFTBUS_HUKS_GENERATE_KEY_ERR;
    }
    LNN_LOGI(LNN_LEDGER, "huks generate new de key");
    return SOFTBUS_OK;
}

static int32_t DeleteDeKeyByHuks(struct HksBlob *keyAlias)
{
    struct HksParamSet *paramSet = NULL;
    struct HksParam keyExistparams[] = {
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_DE},
    };
    int32_t ret = ConstructKeyParamSet(&paramSet, keyExistparams, sizeof(keyExistparams) / sizeof(struct HksParam));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "delete de key ConstructKeyParamSet failed.");
        return ret;
    }
    if (HksKeyExist(keyAlias, paramSet) != HKS_SUCCESS) {
        LNN_LOGD(LNN_LEDGER, "huks de key has deleted");
        HksFreeParamSet(&paramSet);
        return SOFTBUS_OK;
    }
    HksFreeParamSet(&paramSet);
    ret = HksDeleteKey(keyAlias, g_genParamSet);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks de delete key fail, errcode=%{public}d", ret);
        return SOFTBUS_HUKS_DELETE_KEY_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t DeleteCeKeyByHuks(struct HksBlob *keyAlias)
{
    struct HksParamSet *paramSet = NULL;
    struct HksParam keyExistparams[] = {
        { .tag = HKS_TAG_SPECIFIC_USER_ID, .int32Param = DEFAULT_ACCOUNT_ID},
        { .tag = HKS_TAG_AUTH_STORAGE_LEVEL, .uint32Param = HKS_AUTH_STORAGE_LEVEL_CE},
    };
    int32_t ret = ConstructKeyParamSet(&paramSet, keyExistparams, sizeof(keyExistparams) / sizeof(struct HksParam));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "delete ce key ConstructKeyParamSet failed.");
        return ret;
    }
    if (HksKeyExist(keyAlias, paramSet) != HKS_SUCCESS) {
        LNN_LOGD(LNN_LEDGER, "huks ce key has deleted");
        HksFreeParamSet(&paramSet);
        return SOFTBUS_OK;
    }
    HksFreeParamSet(&paramSet);
    ret = HksDeleteKey(keyAlias, g_genCeParamSet);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks delete ce key fail, errcode=%{public}d", ret);
        return SOFTBUS_HUKS_DELETE_KEY_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnGenerateCeKeyByHuks(struct HksBlob *keyAlias)
{
    if (keyAlias == NULL) {
        LNN_LOGE(LNN_LEDGER, "gen ce invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&g_ceParamsLock) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "gen ce mutex fail");
        return SOFTBUS_LOCK_ERR;
    }
    if (!g_isGenCeParams && (GenerateCeKeyByHuks(keyAlias) == SOFTBUS_OK)) {
        LNN_LOGI(LNN_LEDGER, "gen ce param success");
        g_isGenCeParams = true;
    }
    (void)pthread_mutex_unlock(&g_ceParamsLock);
    return SOFTBUS_OK;
}

int32_t LnnGenerateKeyByHuks(struct HksBlob *keyAlias)
{
    if (keyAlias == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = GenerateDeKeyByHuks(keyAlias);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate de key fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnDeleteCeKeyByHuks(struct HksBlob *keyAlias)
{
    if (keyAlias == NULL) {
        LNN_LOGE(LNN_LEDGER, "delete ce invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = DeleteCeKeyByHuks(keyAlias);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "delete ce key fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnDeleteKeyByHuks(struct HksBlob *keyAlias)
{
    if (keyAlias == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = DeleteDeKeyByHuks(keyAlias);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "delete de key fail");
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t LnnEncryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    if (keyAlias == NULL || inData == NULL || outData == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = {sizeof(uint64_t), handleE};
    int32_t ret = HksInit(keyAlias, g_encryptParamSet, &handleEncrypt, NULL);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks encrypt data init fail, errcode=%{public}d", ret);
        return SOFTBUS_HUKS_INIT_FAILED;
    }
    uint8_t *cipher = (uint8_t *)SoftBusCalloc(inData->size);
    if (cipher == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc encrypt data fail");
        return SOFTBUS_MALLOC_ERR;
    }
    struct HksBlob cipherText = {inData->size, cipher};
    ret = UpdateLoopFinishByHuks(&handleEncrypt, g_encryptParamSet, inData, &cipherText);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks encrypt data update and finish fail");
        (void)memset_s(cipher, inData->size, 0x0, inData->size);
        SoftBusFree(cipher);
        return ret;
    }
    outData->size = cipherText.size;
    if (memcpy_s(outData->data, cipherText.size, cipherText.data, cipherText.size) != EOK) {
        LNN_LOGE(LNN_LEDGER, "huks memcpy_s encrypt data fail");
        (void)memset_s(cipher, inData->size, 0x0, inData->size);
        SoftBusFree(cipher);
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(cipher, inData->size, 0x0, inData->size);
    SoftBusFree(cipher);
    return SOFTBUS_OK;
}

int32_t LnnDecryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    if (keyAlias == NULL || inData == NULL || outData == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecrypt = {sizeof(uint64_t), handleD};
    int32_t ret = HksInit(keyAlias, g_decryptParamSet, &handleDecrypt, NULL);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks decrypt data init fail, errcode=%{public}d", ret);
        return SOFTBUS_HUKS_INIT_FAILED;
    }
    uint8_t *plain = (uint8_t *)SoftBusCalloc(inData->size);
    if (plain == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc encrypt data fail");
        return SOFTBUS_MALLOC_ERR;
    }
    struct HksBlob plainText = {inData->size, plain};
    ret = UpdateLoopFinishByHuks(&handleDecrypt, g_decryptParamSet, inData, &plainText);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks decrypt data update and finish fail");
        (void)memset_s(plain, inData->size, 0x0, inData->size);
        SoftBusFree(plain);
        return ret;
    }
    outData->size = plainText.size;
    if (memcpy_s(outData->data, plainText.size, plainText.data, plainText.size) != EOK) {
        LNN_LOGE(LNN_LEDGER, "huks memcpy_s decrypt data fail");
        (void)memset_s(plain, inData->size, 0x0, inData->size);
        SoftBusFree(plain);
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(plain, inData->size, 0x0, inData->size);
    SoftBusFree(plain);
    return SOFTBUS_OK;
}

int32_t LnnCeEncryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    if (keyAlias == NULL || inData == NULL || outData == NULL || inData->size == 0) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = {sizeof(uint64_t), handleE};
    int32_t ret = HksInit(keyAlias, g_ceEncryptParamSet, &handleEncrypt, NULL);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks encrypt data init fail, errcode=%{public}d", ret);
        return SOFTBUS_HUKS_INIT_FAILED;
    }
    uint8_t *cipher = (uint8_t *)SoftBusCalloc(inData->size);
    if (cipher == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc encrypt data fail");
        return SOFTBUS_MALLOC_ERR;
    }
    struct HksBlob cipherText = {inData->size, cipher};
    ret = UpdateLoopFinishByHuks(&handleEncrypt, g_ceEncryptParamSet, inData, &cipherText);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks encrypt data update and finish fail");
        (void)memset_s(cipher, inData->size, 0x0, inData->size);
        SoftBusFree(cipher);
        return ret;
    }
    outData->size = cipherText.size;
    if (memcpy_s(outData->data, cipherText.size, cipherText.data, cipherText.size) != EOK) {
        LNN_LOGE(LNN_LEDGER, "huks memcpy_s encrypt data fail");
        (void)memset_s(cipher, inData->size, 0x0, inData->size);
        SoftBusFree(cipher);
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(cipher, inData->size, 0x0, inData->size);
    SoftBusFree(cipher);
    return SOFTBUS_OK;
}

int32_t LnnCeDecryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    if (keyAlias == NULL || inData == NULL || outData == NULL || inData->size == 0) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecrypt = {sizeof(uint64_t), handleD};
    int32_t ret = HksInit(keyAlias, g_ceDecryptParamSet, &handleDecrypt, NULL);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks decrypt data init fail, errcode=%{public}d", ret);
        return SOFTBUS_HUKS_INIT_FAILED;
    }
    uint8_t *plain = (uint8_t *)SoftBusCalloc(inData->size);
    if (plain == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc encrypt data fail");
        return SOFTBUS_MALLOC_ERR;
    }
    struct HksBlob plainText = {inData->size, plain};
    ret = UpdateLoopFinishByHuks(&handleDecrypt, g_ceDecryptParamSet, inData, &plainText);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks decrypt data update and finish fail");
        (void)memset_s(plain, inData->size, 0x0, inData->size);
        SoftBusFree(plain);
        return ret;
    }
    outData->size = plainText.size;
    if (memcpy_s(outData->data, plainText.size, plainText.data, plainText.size) != EOK) {
        LNN_LOGE(LNN_LEDGER, "huks memcpy_s decrypt data fail");
        (void)memset_s(plain, inData->size, 0x0, inData->size);
        SoftBusFree(plain);
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(plain, inData->size, 0x0, inData->size);
    SoftBusFree(plain);
    return SOFTBUS_OK;
}

int32_t LnnGenerateRandomByHuks(uint8_t *random, uint32_t len)
{
    if (random == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    struct HksBlob tmp = {0};
    tmp.size = len;
    tmp.data = (uint8_t *)SoftBusCalloc(tmp.size);
    if (tmp.data == NULL) {
        LNN_LOGE(LNN_LEDGER, "malloc random key fail");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = HksGenerateRandom(NULL, &tmp);
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "generate random key fail, errcode=%{public}d", ret);
        SoftBusFree(tmp.data);
        return SOFTBUS_HUKS_GENERATE_RANDOM_ERR;
    }
    if (memcpy_s(random, len, tmp.data, len) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s random key fail");
        SoftBusFree(tmp.data);
        return SOFTBUS_MEM_ERR;
    }
    SoftBusFree(tmp.data);
    return SOFTBUS_OK;
}
