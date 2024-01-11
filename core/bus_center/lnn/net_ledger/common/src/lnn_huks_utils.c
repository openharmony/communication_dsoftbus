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

#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"

#define LNN_HUKS_MAX_UPDATE_TIMES 4
#define LNN_HUKS_MAX_UPDATE_SIZE 64
#define LNN_HUKS_MAX_OUTDATA_SIZE (LNN_HUKS_MAX_UPDATE_SIZE * LNN_HUKS_MAX_UPDATE_TIMES)

#define LNN_HUKS_IV_SIZE 16
static uint8_t g_huksIv[LNN_HUKS_IV_SIZE] = {0};

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
    }
};

static struct HksParamSet *g_genParamSet = NULL;
static struct HksParamSet *g_encryptParamSet = NULL;
static struct HksParamSet *g_decryptParamSet = NULL;

static int32_t LoopFinishByHuks(const struct HksBlob *handle, const struct HksParamSet *paramSet,
    const struct HksBlob *inDataSeg, uint8_t *cur, uint32_t *outDataSize)
{
    struct HksBlob outDataFinish = {inDataSeg->size * LNN_HUKS_MAX_UPDATE_TIMES, NULL};
    outDataFinish.data = (uint8_t *)SoftBusCalloc(outDataFinish.size);
    if (outDataFinish.data == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc outDataFinish.data fail");
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = HksFinish(handle, paramSet, inDataSeg, &outDataFinish);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks finish fail, huks errcode=%{public}d", ret);
        SoftBusFree(outDataFinish.data);
        return SOFTBUS_ERR;
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
            return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
    }
    ret = HksAddParams(*paramSet, params, paramcount);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks add param set fail, errcode=%{public}d", ret);
        HksFreeParamSet(paramSet);
        return SOFTBUS_ERR;
    }
    ret = HksBuildParamSet(paramSet);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks build param set fail, errcode=%{public}d", ret);
        HksFreeParamSet(paramSet);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnInitHuksInterface(void)
{
    int32_t ret = HksInitialize();
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "initialize huks fail, errcode=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    if (InitParamSetByHuks(&g_genParamSet, g_genParams,
        sizeof(g_genParams) / sizeof(struct HksParam)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks init gen param set fail");
        return SOFTBUS_ERR;
    }
    if (InitParamSetByHuks(&g_encryptParamSet, g_encryptParams,
        sizeof(g_encryptParams) / sizeof(struct HksParam)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks init encrypt param set fail");
        return SOFTBUS_ERR;
    }
    if (InitParamSetByHuks(&g_decryptParamSet, g_decryptParams,
        sizeof(g_decryptParams) / sizeof(struct HksParam)) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks init decrypt param set fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
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
}

int32_t LnnGenerateKeyByHuks(struct HksBlob *keyAlias)
{
    if (keyAlias == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (HksKeyExist(keyAlias, NULL) == HKS_SUCCESS) {
        LNN_LOGD(LNN_LEDGER, "huks key has generated");
        return SOFTBUS_OK;
    }
    int32_t ret = HksGenerateKey(keyAlias, g_genParamSet, NULL);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks generate key fail, errcode=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnDeleteKeyByHuks(struct HksBlob *keyAlias)
{
    if (keyAlias == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (HksKeyExist(keyAlias, NULL) != HKS_SUCCESS) {
        LNN_LOGD(LNN_LEDGER, "huks key has deleted");
        return SOFTBUS_OK;
    }
    int32_t ret = HksDeleteKey(keyAlias, g_genParamSet);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks delete key fail, errcode=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t LnnEncryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    if (keyAlias == NULL || inData == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t handleE[sizeof(uint64_t)] = {0};
    struct HksBlob handleEncrypt = {sizeof(uint64_t), handleE};
    int32_t ret = HksInit(keyAlias, g_encryptParamSet, &handleEncrypt, NULL);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks encrypt data init fail, errcode=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    uint8_t *cipher = (uint8_t *)SoftBusCalloc(inData->size);
    if (cipher == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc encrypt data fail");
        return SOFTBUS_MEM_ERR;
    }
    struct HksBlob cipherText = {inData->size, cipher};
    if (UpdateLoopFinishByHuks(&handleEncrypt, g_encryptParamSet, inData, &cipherText) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks encrypt data update and finish fail");
        (void)memset_s(cipher, sizeof(cipher), 0x0, sizeof(cipher));
        SoftBusFree(cipher);
        return SOFTBUS_ERR;
    }
    outData->size = cipherText.size;
    if (memcpy_s(outData->data, cipherText.size, cipherText.data, cipherText.size) != EOK) {
        LNN_LOGE(LNN_LEDGER, "huks memcpy_s encrypt data fail");
        (void)memset_s(cipher, sizeof(cipher), 0x0, sizeof(cipher));
        SoftBusFree(cipher);
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(cipher, sizeof(cipher), 0x0, sizeof(cipher));
    SoftBusFree(cipher);
    return SOFTBUS_OK;
}

int32_t LnnDecryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData,
    struct HksBlob *outData)
{
    if (keyAlias == NULL || inData == NULL) {
        LNN_LOGE(LNN_LEDGER, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t handleD[sizeof(uint64_t)] = {0};
    struct HksBlob handleDecrypt = {sizeof(uint64_t), handleD};
    int32_t ret = HksInit(keyAlias, g_decryptParamSet, &handleDecrypt, NULL);
    if (ret != HKS_SUCCESS) {
        LNN_LOGE(LNN_LEDGER, "huks decrypt data init fail, errcode=%{public}d", ret);
        return SOFTBUS_ERR;
    }
    uint8_t *plain = (uint8_t *)SoftBusCalloc(inData->size);
    if (plain == NULL) {
        LNN_LOGE(LNN_LEDGER, "calloc encrypt data fail");
        return SOFTBUS_MEM_ERR;
    }
    struct HksBlob plainText = {inData->size, plain};
    if (UpdateLoopFinishByHuks(&handleDecrypt, g_decryptParamSet, inData, &plainText) != SOFTBUS_OK) {
        LNN_LOGE(LNN_LEDGER, "huks decrypt data update and finish fail");
        (void)memset_s(plain, sizeof(plain), 0x0, sizeof(plain));
        SoftBusFree(plain);
        return SOFTBUS_ERR;
    }
    outData->size = plainText.size;
    if (memcpy_s(outData->data, plainText.size, plainText.data, plainText.size) != EOK) {
        LNN_LOGE(LNN_LEDGER, "huks memcpy_s decrypt data fail");
        (void)memset_s(plain, sizeof(plain), 0x0, sizeof(plain));
        SoftBusFree(plain);
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(plain, sizeof(plain), 0x0, sizeof(plain));
    SoftBusFree(plain);
    return SOFTBUS_OK;
}

int32_t LnnGenerateRandomByHuks(uint8_t *random, uint32_t len)
{
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
        return SOFTBUS_ERR;
    }
    if (memcpy_s(random, len, tmp.data, len) != EOK) {
        LNN_LOGE(LNN_LEDGER, "memcpy_s random key fail");
        SoftBusFree(tmp.data);
        return SOFTBUS_MEM_ERR;
    }
    SoftBusFree(tmp.data);
    return SOFTBUS_OK;
}
