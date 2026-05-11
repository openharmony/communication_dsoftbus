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

static void FillTransTdcPackDataInfo(FuzzedDataProvider &provider, TransTdcPackDataInfo *info)
{
    info->needAck = provider.ConsumeBool();
    info->supportTlv = provider.ConsumeBool();
    info->seq = provider.ConsumeIntegral<int32_t>();
    info->len = provider.ConsumeIntegral<uint32_t>();
}

void TransTdcPackAllDataTest(FuzzedDataProvider &provider)
{
    TransTdcPackDataInfo info;
    (void)memset_s(&info, sizeof(TransTdcPackDataInfo), 0, sizeof(TransTdcPackDataInfo));
    FillTransTdcPackDataInfo(provider, &info);
    DataLenInfo lenInfo;
    (void)memset_s(&lenInfo, sizeof(DataLenInfo), 0, sizeof(DataLenInfo));
    FillDataLenInfo(provider, &lenInfo);
    std::string providerSessionKey = provider.ConsumeBytesAsString(SESSION_KEY_LENGTH - 1);
    char sessionKey[SESSION_KEY_LENGTH] = { 0 };
    if (strcpy_s(sessionKey, SESSION_KEY_LENGTH, providerSessionKey.c_str()) != EOK) {
        return;
    }
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    int32_t flags = provider.ConsumeIntegral<int32_t>();

    (void)TransTdcPackAllData(nullptr, nullptr, nullptr, flags, nullptr);
    info.len = 0;
    (void)TransTdcPackAllData(&info, sessionKey, data, flags, &lenInfo);
    flags = FLAG_ACK;
    (void)TransTdcPackAllData(&info, sessionKey, data, flags, &lenInfo);
    info.supportTlv = true;
    (void)TransTdcPackAllData(&info, sessionKey, data, flags, &lenInfo);
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
    OHOS::TransTdcPackAllDataTest(provider);
    return 0;
}