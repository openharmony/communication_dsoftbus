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

#include "softbusmessageopenchannelmock_fuzzer.h"

#include <cstddef>
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

#include "gtest/gtest.h"

namespace OHOS {
void TransRunAllTest(FuzzedDataProvider &provider)
{
    (void)provider;
    (void)RUN_ALL_TESTS();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    static bool isFirst = true;

    if (isFirst) {
        testing::InitGoogleTest();
        testing::GTEST_FLAG(filter) = "*Fuzz*";
        FuzzedDataProvider provider(data, size);
        OHOS::TransRunAllTest(provider);
        isFirst = false;
    }

    return 0;
}
