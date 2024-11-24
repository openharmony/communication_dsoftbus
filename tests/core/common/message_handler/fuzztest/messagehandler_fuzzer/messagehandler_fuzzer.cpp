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

#include "messagehandler_fuzzer.h"

#include <cstddef>
#include <string>
#include "message_handler.h"

namespace OHOS {
void DoMessageHandlerFuzz(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    SoftBusLooper *looper = GetLooper(LOOP_TYPE_DEFAULT);
    SetLooper(LOOP_TYPE_DEFAULT, looper);
    SetLooperDumpable(looper, true);
    DumpLooper(looper);
    DestroyLooper(looper);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    OHOS::DoMessageHandlerFuzz(data, size);
    return 0;
}
