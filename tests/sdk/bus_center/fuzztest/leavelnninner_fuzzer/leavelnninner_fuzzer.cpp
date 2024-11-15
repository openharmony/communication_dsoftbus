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

#include "leavelnninner_fuzzer.h"
#include <cstddef>
#include <cstring>
#include <securec.h>
#include "softbus_bus_center.h"
#include "client_bus_center_manager.h"
#include "softbus_error_code.h"

namespace OHOS {
    static void OnLeaveLNNResult(const char *networkId, int32_t retCode)
    {
        (void)networkId;
        (void)retCode;
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return true;
        }

        char tmp[65] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, size) != EOK) {
            return true;
        }

        LeaveLNNInner(reinterpret_cast<const char *>(tmp), reinterpret_cast<const char *>(data), OnLeaveLNNResult);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}