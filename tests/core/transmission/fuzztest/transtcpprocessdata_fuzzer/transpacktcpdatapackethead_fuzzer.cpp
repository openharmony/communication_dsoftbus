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

static void FillTcpDataPacketHead(FuzzedDataProvider &provider, TcpDataPacketHead *data)
{
    data->magicNumber = provider.ConsumeIntegral<uint32_t>();
    data->seq = provider.ConsumeIntegral<int32_t>();
    data->flags = provider.ConsumeIntegral<uint32_t>();
    data->dataLen = provider.ConsumeIntegral<uint32_t>();
}

void PackTcpDataPacketHeadTest(FuzzedDataProvider &provider)
{
    TcpDataPacketHead data;
    (void)memset_s(&data, sizeof(TcpDataPacketHead), 0, sizeof(TcpDataPacketHead));
    FillTcpDataPacketHead(provider, &data);

    (void)PackTcpDataPacketHead(&data);
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
    OHOS::PackTcpDataPacketHeadTest(provider);
    return 0;
}