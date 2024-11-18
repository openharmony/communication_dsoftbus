/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <stdbool.h>
#include <stdlib.h>

#include <securec.h>

#include "lnn_common_utils.h"
#include "lnn_log.h"
#include "lnn_oobe_manager.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

bool IsEnableSoftBusHeartbeat(void)
{
    return true;
}

bool IsOOBEState(void)
{
    SoftBusOOBEState state = SOFTBUS_OOBE_RUNNING;
    if (LnnGetOOBEState(&state) != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "get oobe state fail");
        return true;
    }
    return state != SOFTBUS_OOBE_END;
}

bool IsScreenUnlock(void)
{
    return true;
}

int32_t LnnEncryptAesGcm(AesGcmInputParam *in, int32_t keyIndex, uint8_t **out, uint32_t *outLen)
{
    if (in == NULL || out == NULL || outLen == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    (void)keyIndex;
    if (in->dataLen >= UINT32_MAX - OVERHEAD_LEN) {
        LNN_LOGE(LNN_STATE, "dataLen is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t encDataLen = in->dataLen + OVERHEAD_LEN;
    uint8_t *encData = (uint8_t *)SoftBusCalloc(encDataLen);
    if (encData == NULL) {
        LNN_LOGE(LNN_STATE, "calloc encrypt data fail");
        return SOFTBUS_MALLOC_ERR;
    }
    AesGcmCipherKey cipherKey = {.keyLen = in->keyLen};
    if (memcpy_s(cipherKey.key, sizeof(cipherKey.key), in->key, in->keyLen) != EOK) {
        LNN_LOGE(LNN_STATE, "copy session key fail");
        SoftBusFree(encData);
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = SoftBusEncryptData(&cipherKey, in->data, in->dataLen, encData, &encDataLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "SoftBusEncryptData fail=%{public}d", ret);
        SoftBusFree(encData);
        return SOFTBUS_ENCRYPT_ERR;
    }
    *out = encData;
    *outLen = encDataLen;
    return SOFTBUS_OK;
}

int32_t LnnDecryptAesGcm(AesGcmInputParam *in, uint8_t **out, uint32_t *outLen)
{
    if (in == NULL || out == NULL || outLen == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (in->dataLen <= OVERHEAD_LEN) {
        LNN_LOGE(LNN_STATE, "dataLen is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t decDataLen = in->dataLen - OVERHEAD_LEN;
    uint8_t *decData = (uint8_t *)SoftBusCalloc(decDataLen);
    if (decData == NULL) {
        LNN_LOGE(LNN_STATE, "malloc decrypt data fail");
        return SOFTBUS_MALLOC_ERR;
    }
    AesGcmCipherKey cipherKey = {.keyLen = in->keyLen};
    if (memcpy_s(cipherKey.key, sizeof(cipherKey.key), in->key, in->keyLen) != EOK) {
        LNN_LOGE(LNN_STATE, "copy session key fail");
        SoftBusFree(decData);
        return SOFTBUS_MEM_ERR;
    }
    int32_t ret = SoftBusDecryptData(&cipherKey, in->data, in->dataLen, decData, &decDataLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        LNN_LOGE(LNN_STATE, "SoftBusDecryptData fail=%{public}d", ret);
        SoftBusFree(decData);
        return SOFTBUS_ENCRYPT_ERR;
    }
    *out = decData;
    *outLen = decDataLen;
    return SOFTBUS_OK;
}
