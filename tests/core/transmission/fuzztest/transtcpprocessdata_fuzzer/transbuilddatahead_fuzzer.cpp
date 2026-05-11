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

namespace OHOS {
void BuildDataHeadTest(FuzzedDataProvider &provider)
{
    DataHead pktHead;
    (void)memset_s(&pktHead, sizeof(DataHead), 0, sizeof(DataHead));
    pktHead.magicNum = provider.ConsumeIntegral<uint32_t>();
    pktHead.tlvCount = provider.ConsumeIntegral<uint8_t>();
    int32_t finalSeq = provider.ConsumeIntegral<int32_t>();
    int32_t flags = provider.ConsumeIntegral<int32_t>();
    uint32_t dataLen = provider.ConsumeIntegral<uint32_t>();
    int32_t tlvBufferSize = 0;

    (void)BuildDataHead(nullptr, finalSeq, flags, dataLen, nullptr);
    (void)BuildDataHead(&pktHead, finalSeq, flags, dataLen, &tlvBufferSize);
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
    OHOS::BuildDataHeadTest(provider);
    return 0;
}