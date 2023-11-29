/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "softbuslog_fuzzer.h"

#include <securec.h>

#include "softbus_log_old.h"

namespace OHOS {
static constexpr size_t MAX_BUFFER_LEN = 100;

static void AnonymizesTest(const char *buffer)
{
    Anonymizes(buffer, 10);
}

static void AnonyPacketPrintoutTest(const char *buffer, size_t size)
{
    AnonyPacketPrintout(SOFTBUS_LOG_DISC, buffer, buffer, size);
}

static void AnonyDevIdTest(const char *buffer)
{
    char *outName = nullptr;
    AnonyDevId(&outName, buffer);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < OHOS::MAX_BUFFER_LEN) {
        return 0;
    }

    char buffer[OHOS::MAX_BUFFER_LEN] = { 0 };
    if (memcpy_s(buffer, sizeof(buffer) - 1, data, size) != EOK) {
        return 0;
    }

    OHOS::AnonymizesTest(buffer);
    OHOS::AnonyPacketPrintoutTest(buffer, OHOS::MAX_BUFFER_LEN - 1);
    OHOS::AnonyDevIdTest(buffer);
    return 0;
}