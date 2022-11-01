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

#include "convertbtmactostr_fuzzer.h"
#include "softbus_utils.h"
#include <cctype>
#include <cstdlib>
#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_common.h"
#include "softbus_def.h"

namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
    {
        if (rawData == nullptr) {
            return false;
        }
        char binMac[64] = {0};
        ConvertBtMacToStr(binMac, size, rawData, size);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}