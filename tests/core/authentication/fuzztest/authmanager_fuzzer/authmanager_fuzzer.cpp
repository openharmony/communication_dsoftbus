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

#include "authmanager_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "auth_log.h"
#include "gtest/gtest.h"

namespace OHOS {
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    static bool isFirst = true;
    if (isFirst) {
        testing::InitGoogleTest();
        auto result = RUN_ALL_TESTS();
        AUTH_LOGI(AUTH_TEST, "result=%{public}d", result);
        isFirst = false;
    }
    return 0;
}
}