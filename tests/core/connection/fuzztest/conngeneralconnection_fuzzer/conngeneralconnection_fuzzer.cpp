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

#include "gtest/gtest.h"
#include "conn_log.h"
#include "fuzz_data_generator.h"

namespace OHOS {
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    DataGenerator::Write(data, size);
    testing::InitGoogleTest();
    auto result = RUN_ALL_TESTS();
    CONN_LOGI(CONN_WIFI_DIRECT, "result=%{public}d", result);
    DataGenerator::Clear();
    sleep(1);
    return 0;
}