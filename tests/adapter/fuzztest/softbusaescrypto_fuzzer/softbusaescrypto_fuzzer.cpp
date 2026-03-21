/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

using namespace std;
namespace {
class TestEnv {
public:
    TestEnv()
    {
        isInited_ = true;
    }
    ~TestEnv()
    {
        isInited_ = false;
    }

    bool IsEnvInited()
    {
        return isInited_;
    }

private:
    volatile bool isInited_ = false;
};
} // namespace

namespace OHOS {
bool SoftBusGenerateHmacHashFuzzTest(FuzzedDataProvider &provider)
{
    vector<uint8_t> data = provider.ConsumeRemainingBytes<uint8_t>();
    EncryptKey randomKey;
    (void)memset_s(&randomKey, sizeof(EncryptKey), 0, sizeof(EncryptKey));
    randomKey.key = data.data();
    randomKey.len = data.size();
    uint8_t hash[SHA256_MAC_LEN] = { 0 };
    const uint8_t *ptrToData = data.data();
    SoftBusGenerateHmacHash(&randomKey, ptrToData, data.size(), hash, SHA256_MAC_LEN);
    return true;
}

bool SoftBusAesCfbRootEncryptFuzzTest(FuzzedDataProvider &provider)
{
    AesOutputData encryptOutData = { 0 };
    AesOutputData decryptOutData = { 0 };

    vector<uint8_t> data = provider.ConsumeRemainingBytes<uint8_t>();
    AesInputData encryptInData;
    (void)memset_s(&encryptInData, sizeof(AesInputData), 0, sizeof(AesInputData));
    encryptInData.data = data.data();
    encryptInData.len = data.size();

    vector<uint8_t> key1 = provider.ConsumeRemainingBytes<uint8_t>();
    EncryptKey randomKey;
    (void)memset_s(&randomKey, sizeof(EncryptKey), 0, sizeof(EncryptKey));
    randomKey.key = key1.data();
    randomKey.len = key1.size();

    vector<uint8_t> key2 = provider.ConsumeRemainingBytes<uint8_t>();
    EncryptKey rootKey;
    (void)memset_s(&rootKey, sizeof(EncryptKey), 0, sizeof(EncryptKey));
    rootKey.key = key2.data();
    rootKey.len = key2.size();

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
    AesOutputData encryptOutData = {0};
    AesOutputData decryptOutData = {0};

    vector<uint8_t> data = provider.ConsumeRemainingBytes<uint8_t>();
    AesInputData encryptInData;
    (void)memset_s(&encryptInData, sizeof(AesInputData), 0, sizeof(AesInputData));
    encryptInData.data = data.data();
    encryptInData.len = data.size();

    vector<uint8_t> key = provider.ConsumeRemainingBytes<uint8_t>();
    AesCipherKey cipherKey;
    (void)memset_s(&cipherKey, sizeof(AesCipherKey), 0, sizeof(AesCipherKey));
    cipherKey.key = key.data();
    cipherKey.keyLen = key.size();
    cipherKey.iv = key.data();
    cipherKey.ivLen = key.size();

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
    vector<uint8_t> inputData = provider.ConsumeRemainingBytes<uint8_t>();
    AesInputData encryptInData;
    (void)memset_s(&encryptInData, sizeof(AesInputData), 0, sizeof(AesInputData));
    encryptInData.data = inputData.data();
    encryptInData.len = inputData.size();

    vector<uint8_t> key1 = provider.ConsumeRemainingBytes<uint8_t>();
    AesCipherKey cipherKey;
    (void)memset_s(&cipherKey, sizeof(AesCipherKey), 0, sizeof(AesCipherKey));
    cipherKey.key = key1.data();
    cipherKey.keyLen = key1.size();
    cipherKey.iv = key1.data();
    cipherKey.ivLen = key1.size();

    vector<uint8_t> key2 = provider.ConsumeRemainingBytes<uint8_t>();
    AesCipherKey cipherKeyCopy;
    (void)memset_s(&cipherKeyCopy, sizeof(AesCipherKey), 0, sizeof(AesCipherKey));
    cipherKeyCopy.key = key2.data();
    cipherKeyCopy.keyLen = key2.size();
    cipherKeyCopy.iv = key2.data();
    cipherKeyCopy.ivLen = key2.size();
    return EncryptSubFunctionFuzzTest(encryptInData, cipherKey, cipherKeyCopy);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }

    static TestEnv env;
    if (!env.IsEnvInited()) {
        return -1;
    }
    FuzzedDataProvider provider(data, size);
    OHOS::SoftBusGenerateHmacHashFuzzTest(provider);
    OHOS::SoftBusAesCfbRootEncryptFuzzTest(provider);
    OHOS::SoftBusAesGcmEncryptFuzzTest(provider);
    OHOS::SoftBusAesCfbEncryptFuzzTest(provider);
    return 0;
}