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

static void FillDataLenInfo(FuzzedDataProvider &provider, DataLenInfo *lenInfo)
{
    lenInfo->outLen = provider.ConsumeIntegral<uint32_t>();
    lenInfo->tlvHeadLen = provider.ConsumeIntegral<uint32_t>();
}

void TransTdcSendDataTest(FuzzedDataProvider &provider)
{
    DataLenInfo lenInfo;
    (void)memset_s(&lenInfo, sizeof(DataLenInfo), 0, sizeof(DataLenInfo));
    FillDataLenInfo(provider, &lenInfo);
    bool supportTlv = provider.ConsumeBool();
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    uint32_t len = provider.ConsumeIntegralInRange<uint32_t>(0, OVERHEAD_LEN);
    char buf[OVERHEAD_LEN] = { 0 };

    (void)TransTdcSendData(nullptr, supportTlv, fd, len, nullptr);
    fd = -1;
    (void)TransTdcSendData(&lenInfo, supportTlv, fd, len, buf);

    lenInfo.outLen = len + OVERHEAD_LEN;
    (void)TransTdcSendData(&lenInfo, supportTlv, fd, len, buf);
    supportTlv = true;
    (void)TransTdcSendData(&lenInfo, supportTlv, fd, len, buf);
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
    OHOS::TransTdcSendDataTest(provider);
    return 0;
}