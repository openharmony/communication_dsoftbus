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

#include "comm_log.h"
#include "softbus_adapter_crypto.h"
#include "softbus_error_code.h"
#include "softbus_tlv_utils.h"

namespace OHOS {

static void FuzzSetTlvBinary(uint8_t tSize, uint8_t lSize, const uint8_t *data, size_t size)
{
    TlvObject *obj = CreateTlvObject(tSize, lSize);
    COMM_CHECK_AND_RETURN_LOGE(obj != NULL, COMM_UTILS, "create tlv obj fail");
    (void)SetTlvBinary(obj, data, size);
    DestroyTlvObject(obj);
}

static void FuzzAddTlvMember(uint8_t tSize, uint8_t lSize, const uint8_t *data, size_t size)
{
    TlvObject *obj = CreateTlvObject(tSize, lSize);
    COMM_CHECK_AND_RETURN_LOGE(obj != NULL, COMM_UTILS, "create tlv obj fail");
    uint32_t type = 0;
    uint32_t length = size;
    uint32_t offset = 0;
    for (; offset < size && length > 0; type++) {
        length = (SoftBusCryptoRand() % (size - offset));
        (void)AddTlvMember(obj, type, length, data + offset);
        offset += length;
    }
    DestroyTlvObject(obj);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return false;
    }
    FuzzSetTlvBinary(UINT8_T, UINT8_T, data, size);
    FuzzSetTlvBinary(UINT8_T, UINT16_T, data, size);
    FuzzSetTlvBinary(UINT8_T, UINT32_T, data, size);
    FuzzSetTlvBinary(UINT16_T, UINT8_T, data, size);
    FuzzSetTlvBinary(UINT16_T, UINT16_T, data, size);
    FuzzSetTlvBinary(UINT16_T, UINT32_T, data, size);
    FuzzSetTlvBinary(UINT32_T, UINT8_T, data, size);
    FuzzSetTlvBinary(UINT32_T, UINT16_T, data, size);
    FuzzSetTlvBinary(UINT32_T, UINT32_T, data, size);

    FuzzAddTlvMember(UINT8_T, UINT8_T, data, size);
    FuzzAddTlvMember(UINT8_T, UINT16_T, data, size);
    FuzzAddTlvMember(UINT8_T, UINT32_T, data, size);
    FuzzAddTlvMember(UINT16_T, UINT8_T, data, size);
    FuzzAddTlvMember(UINT16_T, UINT16_T, data, size);
    FuzzAddTlvMember(UINT16_T, UINT32_T, data, size);
    FuzzAddTlvMember(UINT32_T, UINT8_T, data, size);
    FuzzAddTlvMember(UINT32_T, UINT16_T, data, size);
    FuzzAddTlvMember(UINT32_T, UINT32_T, data, size);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
