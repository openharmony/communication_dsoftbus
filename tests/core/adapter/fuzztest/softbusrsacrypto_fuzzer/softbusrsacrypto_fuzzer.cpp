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
#include <securec.h>

#include "comm_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

namespace OHOS {
bool SoftBusRsaEncryptFuzzTest(const uint8_t *data, size_t size)
{
    uint32_t encryptedDataLen = 0;
    uint8_t *encryptedData = nullptr;
    PublicKey peerPublicKey = { data, size };

    if (SoftBusRsaEncrypt(data, size, &peerPublicKey, &encryptedData, &encryptedDataLen) != SOFTBUS_OK) {
        COMM_LOGE(COMM_TEST, "SoftBusRsaEncrypt failed!");
        return false;
    }
    SoftBusFree(encryptedData);
    return true;
}

bool SoftBusRsaDecryptFuzzTest(const uint8_t *data, size_t size)
{
    uint32_t decryptedDataLen = 0;
    uint8_t *decryptedData = nullptr;

    if (SoftBusRsaDecrypt(data, size, &decryptedData, &decryptedDataLen) != SOFTBUS_OK) {
        COMM_LOGE(COMM_TEST, "SoftBusRsaDecrypt failed!");
        return false;
    }
    SoftBusFree(decryptedData);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }

    OHOS::SoftBusRsaEncryptFuzzTest(data, size);
    OHOS::SoftBusRsaDecryptFuzzTest(data, size);
    return 0;
}