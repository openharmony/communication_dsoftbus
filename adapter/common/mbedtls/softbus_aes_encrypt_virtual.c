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
#include "softbus_error_code.h"

int32_t SoftBusGenerateHmacHash(
    const EncryptKey *randomKey, const uint8_t *rootKey, uint32_t rootKeyLen, uint8_t *hash, uint32_t hashLen)
{
    (void)randomKey;
    (void)rootKey;
    (void)rootKeyLen;
    (void)hash;
    (void)hashLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SoftBusAesCfbRootEncrypt(const AesInputData *inData, const EncryptKey *randomKey, EncryptKey *rootKey,
    int32_t encMode, AesOutputData *outData)
{
    (void)inData;
    (void)randomKey;
    (void)rootKey;
    (void)encMode;
    (void)outData;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SoftBusAesCfbEncrypt(
    const AesInputData *inData, AesCipherKey *cipherKey, int32_t encMode, AesOutputData *outData)
{
    (void)inData;
    (void)cipherKey;
    (void)encMode;
    (void)outData;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t SoftBusAesGcmEncrypt(
    const AesInputData *inData, AesCipherKey *cipherKey, int32_t encMode, AesOutputData *outData)
{
    (void)inData;
    (void)cipherKey;
    (void)encMode;
    (void)outData;
    return SOFTBUS_NOT_IMPLEMENT;
}

