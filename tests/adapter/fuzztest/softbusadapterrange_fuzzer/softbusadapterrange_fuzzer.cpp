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

#include "softbusadapterrange_fuzzer.h"

#include <securec.h>
#include "softbus_adapter_range.h"

namespace OHOS {
static void SoftBusAdapterRangeFuzzTest(const uint8_t* data, size_t size)
{
    if (size < sizeof(SoftBusRangeParam)) {
        return;
    }

    SoftBusRangeParam rangeParam;
    if (memcpy_s(&rangeParam, sizeof(SoftBusRangeParam), data, sizeof(SoftBusRangeParam)) != EOK) {
        return;
    }

    int32_t range;
    SoftBusBleRange(&rangeParam, &range);

    int8_t power;
    SoftBusGetBlePower(&power);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    /* Run your code on data */
    OHOS::SoftBusAdapterRangeFuzzTest(data, size);
    return 0;
}
