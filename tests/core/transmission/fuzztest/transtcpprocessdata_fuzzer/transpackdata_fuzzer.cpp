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

#include "transtcpprocessdata_fuzzer.h"

#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <vector>

#include "fuzz_data_generator.h"

#define DATA_MIN_LEN 0
#define DATA_MAX_LEN 4194304

namespace OHOS {
void TransPackDataTest(FuzzedDataProvider &provider)
{
    uint32_t dataLen = provider.ConsumeIntegralInRange<uint32_t>(DATA_MIN_LEN, DATA_MAX_LEN);
    int32_t finalSeq = provider.ConsumeIntegral<int32_t>();
    int32_t flags = provider.ConsumeIntegralInRange<int32_t>(FLAG_BYTES, FLAG_SET_LOW_LATENCY);

    char *buf = TransPackData(dataLen, finalSeq, flags);
    if (buf != nullptr) {
        SoftBusFree(buf);
    }
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TransTcpProcessData testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::TransPackDataTest(provider);
    return 0;
}