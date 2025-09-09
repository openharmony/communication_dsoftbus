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
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>

#include "comm_log.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

const uint32_t ENCRYPT_RANDOM_MAX = 2000;
using namespace std;
namespace OHOS {
bool SoftBusGenerateHmacHashFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t size = provider.ConsumeIntegral<int32_t>();
    string stringData = provider.ConsumeBytesAsString(size);
    size = stringData.size();
    const uint8_t *data = reinterpret_cast<const uint8_t *>(stringData.data());
    uint8_t hash[SHA256_MAC_LEN] = { 0 };
    EncryptKey randomKey = { data, size };
    SoftBusGenerateHmacHash(&randomKey, data, size, hash, SHA256_MAC_LEN);
    return true;
}

bool SoftBusAesCfbRootEncryptFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t size = provider.ConsumeIntegral<int32_t>();
    string stringData = provider.ConsumeBytesAsString(size);
    size = stringData.size();
    const uint8_t *data = reinterpret_cast<const uint8_t *>(stringData.data());
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

bool SoftBusAesGcmEncryptFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t size = provider.ConsumeIntegral<int32_t>();
    string stringData = provider.ConsumeBytesAsString(size);
    size = stringData.size();
    const uint8_t *data = reinterpret_cast<const uint8_t *>(stringData.data());
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

static bool EncryptSubFunctionFuzzTest(AesInputData &encryptInData, AesCipherKey &cipherKey,
    AesCipherKey &cipherKeyCopy) 
{
    AesOutputData encryptOutData = {0};
    AesOutputData decryptOutData = {0};
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

bool SoftBusAesCfbEncryptFuzzTest(FuzzedDataProvider &provider)
{
    uint32_t size = provider.ConsumeIntegral<int32_t>();
    string stringData = provider.ConsumeBytesAsString(size);
    uint8_t randomSession[ENCRYPT_RANDOM_MAX];
    uint8_t randomIv[ENCRYPT_RANDOM_MAX];
    uint8_t randomSessionCopy[ENCRYPT_RANDOM_MAX];
    uint8_t randomIvCopy[ENCRYPT_RANDOM_MAX];

    if (memcpy_s(randomSession, ENCRYPT_RANDOM_MAX - 1, stringData.data(), stringData.size()) != EOK) {
        COMM_LOGE(COMM_TEST, "randomSession memcpy_s failed!");
        return false;
    }
    string stringData1 = provider.ConsumeBytesAsString(size);
    if (memcpy_s(randomIv, ENCRYPT_RANDOM_MAX - 1, stringData1.data(), stringData1.size()) != EOK) {
        COMM_LOGE(COMM_TEST, "randomIv memcpy_s failed!");
        return false;
    }
    string stringData2 = provider.ConsumeBytesAsString(size);
    if (memcpy_s(randomSessionCopy, ENCRYPT_RANDOM_MAX - 1, stringData2.data(), stringData2.size()) != EOK) {
        COMM_LOGE(COMM_TEST, "randomSessionCopy memcpy_s failed!");
        return false;
    }
    string stringData3 = provider.ConsumeBytesAsString(size);
    if (memcpy_s(randomIvCopy, ENCRYPT_RANDOM_MAX - 1, stringData2.data(), stringData2.size()) != EOK) {
        COMM_LOGE(COMM_TEST, "randomIvCopy memcpy_s failed!");
        return false;
    }
    string stringData4 = provider.ConsumeBytesAsString(size);
    const uint8_t *data4 = reinterpret_cast<const uint8_t *>(stringData4.data());
    size_t size4 = stringData4.size();
    AesInputData encryptInData = { data4, size4 };
    AesCipherKey cipherKey = { randomSession, ENCRYPT_RANDOM_MAX - 1, randomIv, ENCRYPT_RANDOM_MAX - 1 };
    AesCipherKey cipherKeyCopy = { randomSessionCopy, ENCRYPT_RANDOM_MAX - 1, randomIvCopy, ENCRYPT_RANDOM_MAX - 1 };
    return EncryptSubFunctionFuzzTest(encryptInData, cipherKey, cipherKeyCopy);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);
    OHOS::SoftBusGenerateHmacHashFuzzTest(provider);
    OHOS::SoftBusAesCfbRootEncryptFuzzTest(provider);
    OHOS::SoftBusAesGcmEncryptFuzzTest(provider);
    OHOS::SoftBusAesCfbEncryptFuzzTest(provider);
    return 0;
}