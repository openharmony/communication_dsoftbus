/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include "conn_log.h"
#include "fuzz_data_generator.h"
#include "fuzz_environment.h"

namespace OHOS {
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr || size < sizeof(int32_t)) {
        CONN_LOGE(CONN_TEST, "Invalid param");
        return 0;
    }
    std::cout << "llvm fuzz enter" << std::endl;
    CONN_LOGI(CONN_TEST, "llvm fuzz enter");

    DataGenerator::Write(data, size);
    OHOS::SoftBus::FuzzEnvironment::EnableFuzz();
    testing::InitGoogleTest();
    testing::GTEST_FLAG(filter) = "*Fuzz*";
    auto result = RUN_ALL_TESTS();

    DataGenerator::Clear();
    return result;
}