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
void TransTdcRecvFirstDataTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    size_t len = provider.ConsumeIntegral<uint32_t>();
    int32_t recvLen = 0;
    char *recvBuf = static_cast<char *>(SoftBusCalloc(len));

    (void)TransTdcRecvFirstData(channelId, nullptr, nullptr, fd, len);
    fd = -1;
    (void)TransTdcRecvFirstData(channelId, recvBuf, &recvLen, fd, len);

    len = 0;
    (void)TransTdcRecvFirstData(channelId, recvBuf, &recvLen, fd, len);
    SoftBusFree(recvBuf);
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
    OHOS::TransTdcRecvFirstDataTest(provider);
    return 0;
}