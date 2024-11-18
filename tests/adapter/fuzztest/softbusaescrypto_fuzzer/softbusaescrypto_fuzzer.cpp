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

#include <cstring>
#include <securec.h>

#include "comm_log.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

namespace OHOS {
bool SoftBusGenerateHmacHashFuzzTest(const uint8_t *data, size_t size)
{
    uint8_t hash[SHA256_MAC_LEN] = { 0 };
    EncryptKey randomKey = { data, size };
    SoftBusGenerateHmacHash(&randomKey, data, size, hash, SHA256_MAC_LEN);
    return true;
}

bool SoftBusAesCfbRootEncryptFuzzTest(const uint8_t *data, size_t size)
{
    AesOutputData encryptOutData = { 0 };
    AesOutputData decryptOutData = { 0 };

    AesInputData encryptInData = { data, size };
    EncryptKey randomKey = { data, size };
    EncryptKey rootKey = { data, size };

    if (SoftBusAesCfbRootEncrypt(&encryptInData, &randomKey, &rootKey, ENCRYPT_MODE, &encryptOutData) != SOFTBUS_OK) {
        COMM_LOGE(COMM_TEST, "SoftBus AesCfbRootEncrypt failed!");
        return false;
    }
    if (SoftBusAesCfbRootEncrypt(
        (const AesInputData *)&encryptOutData, &randomKey, &rootKey, DECRYPT_MODE, &decryptOutData) != SOFTBUS_OK) {
        COMM_LOGE(COMM_TEST, "SoftBus AesCfbRootDecrypt failed!");
        SoftBusFree(encryptOutData.data);
        return false;
    }
    if (memcmp((const char *)decryptOutData.data, (const char *)encryptInData.data, decryptOutData.len) != 0) {
        COMM_LOGE(COMM_TEST, "memcmp failed!");
        SoftBusFree(encryptOutData.data);
        SoftBusFree(decryptOutData.data);
        return false;
    }
    SoftBusFree(encryptOutData.data);
    SoftBusFree(decryptOutData.data);
    return true;
}

bool SoftBusAesGcmEncryptFuzzTest(const uint8_t *data, size_t size)
{
    AesOutputData encryptOutData = { 0 };
    AesOutputData decryptOutData = { 0 };

    AesInputData encryptInData = { data, size };
    AesCipherKey cipherKey = { (uint8_t *)data, size, (uint8_t *)data, size };

    if (SoftBusAesGcmEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, &encryptOutData) != SOFTBUS_OK) {
        COMM_LOGE(COMM_TEST, "SoftBus AesGcmEncrypt failed!");
        return false;
    }
    if (SoftBusAesGcmEncrypt((const AesInputData *)&encryptOutData, &cipherKey, DECRYPT_MODE, &decryptOutData) !=
        SOFTBUS_OK) {
        COMM_LOGE(COMM_TEST, "SoftBus AesGcmDecrypt failed!");
        SoftBusFree(encryptOutData.data);
        return false;
    }
    if (memcmp((const char *)decryptOutData.data, (const char *)encryptInData.data, decryptOutData.len) != 0) {
        COMM_LOGE(COMM_TEST, "memcmp failed!");
        SoftBusFree(encryptOutData.data);
        SoftBusFree(decryptOutData.data);
        return false;
    }
    SoftBusFree(encryptOutData.data);
    SoftBusFree(decryptOutData.data);
    return true;
}

bool SoftBusAesCfbEncryptFuzzTest(const uint8_t *data, size_t size)
{
    uint8_t randomSession[size];
    uint8_t randomIv[size];
    uint8_t randomSessionCopy[size];
    uint8_t randomIvCopy[size];
    AesOutputData encryptOutData = { 0 };
    AesOutputData decryptOutData = { 0 };

    if (memcpy_s(randomSession, size, data, size) != EOK) {
        COMM_LOGE(COMM_TEST, "randomSession memcpy_s failed!");
        return false;
    }
    if (memcpy_s(randomIv, size, data, size) != EOK) {
        COMM_LOGE(COMM_TEST, "randomIv memcpy_s failed!");
        return false;
    }
    if (memcpy_s(randomSessionCopy, size, data, size) != EOK) {
        COMM_LOGE(COMM_TEST, "randomSessionCopy memcpy_s failed!");
        return false;
    }
    if (memcpy_s(randomIvCopy, size, data, size) != EOK) {
        COMM_LOGE(COMM_TEST, "randomIvCopy memcpy_s failed!");
        return false;
    }

    AesInputData encryptInData = { data, size };
    AesCipherKey cipherKey = { randomSession, size, randomIv, size };
    AesCipherKey cipherKeyCopy = { randomSessionCopy, size, randomIvCopy, size };

    if (SoftBusAesCfbEncrypt(&encryptInData, &cipherKey, ENCRYPT_MODE, &encryptOutData) != SOFTBUS_OK) {
        COMM_LOGE(COMM_TEST, "SoftBus AesCfbEncrypt failed!");
        return false;
    }
    if (SoftBusAesCfbEncrypt((const AesInputData *)&encryptOutData, &cipherKeyCopy, DECRYPT_MODE, &decryptOutData) !=
        SOFTBUS_OK) {
        COMM_LOGE(COMM_TEST, "SoftBus AesCfbDecrypt failed!");
        SoftBusFree(encryptOutData.data);
        return false;
    }
    if (memcmp((const char *)decryptOutData.data, (const char *)encryptInData.data, decryptOutData.len) != 0) {
        COMM_LOGE(COMM_TEST, "memcmp failed!");
        SoftBusFree(encryptOutData.data);
        SoftBusFree(decryptOutData.data);
        return false;
    }
    SoftBusFree(encryptOutData.data);
    SoftBusFree(decryptOutData.data);
    return true;
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }

    OHOS::SoftBusGenerateHmacHashFuzzTest(data, size);
    OHOS::SoftBusAesCfbRootEncryptFuzzTest(data, size);
    OHOS::SoftBusAesGcmEncryptFuzzTest(data, size);
    OHOS::SoftBusAesCfbEncryptFuzzTest(data, size);
    return 0;
}