/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "softbustlvutils_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "comm_log.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_tlv_utils.h"

namespace OHOS {
static void FuzzSetTlvBinary(uint8_t tSize, uint8_t lSize, const uint8_t *data, uint32_t dataSize)
{
    TlvObject *obj = CreateTlvObject(tSize, lSize);
    COMM_CHECK_AND_RETURN_LOGE(obj != nullptr, COMM_UTILS, "create tlv obj fail");
    (void)SetTlvBinary(obj, data, dataSize);
    uint8_t *output = nullptr;
    uint32_t outputSize = 0;
    int32_t ret = GetTlvBinary(obj, &output, &outputSize);
    if (ret == SOFTBUS_OK) {
        SoftBusFree(output);
        output = nullptr;
    }
    DestroyTlvObject(obj);
}

static void FuzzAddTlvMemberByVariableType(uint8_t tSize, uint8_t lSize, FuzzedDataProvider &provider)
{
    TlvObject *obj = CreateTlvObject(tSize, lSize);
    COMM_CHECK_AND_RETURN_LOGE(obj != nullptr, COMM_UTILS, "create tlv obj fail");

    uint32_t type = provider.ConsumeIntegral<uint32_t>();
    uint8_t valueU8 = provider.ConsumeIntegral<uint8_t>();
    AddTlvMemberU8(obj, type, valueU8);
    uint8_t outputU8 = provider.ConsumeIntegral<uint8_t>();
    GetTlvMemberU8(obj, type, &outputU8);
    uint16_t valueU16 = provider.ConsumeIntegral<uint16_t>();
    AddTlvMemberU16(obj, type, valueU16);
    uint16_t outputU16 = provider.ConsumeIntegral<uint16_t>();
    GetTlvMemberU16(obj, type, &outputU16);
    uint32_t valueU32 = provider.ConsumeIntegral<uint32_t>();
    AddTlvMemberU32(obj, type, valueU32);
    uint32_t outputU32 = provider.ConsumeIntegral<uint32_t>();
    GetTlvMemberU32(obj, type, &outputU32);
    uint64_t valueU64 = provider.ConsumeIntegral<uint64_t>();
    AddTlvMemberU64(obj, type, valueU64);
    uint64_t outputU64 = provider.ConsumeIntegral<uint64_t>();
    GetTlvMemberU64(obj, type, &outputU64);
    uint8_t buffer = provider.ConsumeIntegral<uint8_t>();
    uint32_t size = sizeof(buffer);
    GetTlvMemberWithEstimatedBuffer(obj, type, &buffer, &size);

    DestroyTlvObject(obj);
}

static void DoSomethingInterestingWithMyAPI(FuzzedDataProvider &provider)
{
    uint8_t tSize = provider.ConsumeIntegralInRange<uint8_t>(UINT8_T, UINT32_T);
    uint8_t lSize = provider.ConsumeIntegralInRange<uint8_t>(UINT8_T, UINT32_T);
    size_t blobSize = provider.ConsumeIntegralInRange<size_t>(0, MAX_TLV_BINARY_LENGTH);
    std::vector<uint8_t> blobData = provider.ConsumeBytes<uint8_t>(blobSize);
    uint8_t *data = blobData.data();
    uint32_t dataSize = blobData.size();
    FuzzSetTlvBinary(tSize, lSize, data, dataSize);
    FuzzAddTlvMemberByVariableType(tSize, lSize, provider);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return -1;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(provider);
    return 0;
}
