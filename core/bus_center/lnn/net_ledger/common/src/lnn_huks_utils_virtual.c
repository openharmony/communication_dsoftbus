/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "softbus_error_code.h"

int32_t LnnGenerateKeyByHuks(struct HksBlob *keyAlias)
{
    (void)keyAlias;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGenerateCeKeyByHuks(struct HksBlob *keyAlias, bool isUnlocked)
{
    (void)keyAlias;
    (void)isUnlocked;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDeleteKeyByHuks(struct HksBlob *keyAlias)
{
    (void)keyAlias;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDeleteCeKeyByHuks(struct HksBlob *keyAlias, bool isUnlocked)
{
    (void)keyAlias;
    (void)isUnlocked;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnEncryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData)
{
    (void)keyAlias;
    (void)inData;
    (void)outData;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnDecryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData)
{
    (void)keyAlias;
    (void)inData;
    (void)outData;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnCeEncryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData)
{
    (void)keyAlias;
    (void)inData;
    (void)outData;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnCeDecryptDataByHuks(const struct HksBlob *keyAlias, const struct HksBlob *inData, struct HksBlob *outData)
{
    (void)keyAlias;
    (void)inData;
    (void)outData;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGenerateRandomByHuks(uint8_t *randomKey, uint32_t len)
{
    (void)randomKey;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnInitHuksInterface(void)
{
    return SOFTBUS_OK;
}

void LnnDeinitHuksInterface(void)
{
}
