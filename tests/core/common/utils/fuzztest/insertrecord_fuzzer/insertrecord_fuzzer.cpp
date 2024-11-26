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

#include "insertrecord_fuzzer.h"

#include <securec.h>
#include <unistd.h>

#include "sqlite3_utils.h"

namespace OHOS {
static constexpr size_t MAX_BUFFER_LEN = 100;
bool InsertRecordFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return true;
    }

    DbContext *ctx = nullptr;
    uint8_t buff[OHOS::MAX_BUFFER_LEN] = { 0 };
    if (memcpy_s(buff, sizeof(buff) - 1, data, size) != EOK) {
        return false;
    }
    InsertRecord(ctx, TABLE_TRUSTED_DEV_INFO, buff);
    InsertRecord(ctx, TABLE_NAME_ID_MAX, buff);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::InsertRecordFuzzTest(data, size);
    return 0;
}
