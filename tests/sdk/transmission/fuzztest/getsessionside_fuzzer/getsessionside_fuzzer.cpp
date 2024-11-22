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

#include "getsessionside_fuzzer.h"

#include <cstddef>

#include "session.h"

namespace OHOS {
    void GetSessionSideTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int)) {
            return;
        }
        int sessionId = *(reinterpret_cast<const int *>(data));

        GetSessionSide(sessionId);
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetSessionSideTest(data, size);
    return 0;
}
