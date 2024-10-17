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

#include "streamdepacketizer_fuzzer.h"
#include "stream_depacketizer.h"
#include "common_inner.h"
#include "i_stream.h"
#include "stream_common.h"
#include "softbus_adapter_crypto.h"
#include <securec.h>
#include <cstddef>
#include <cstdint>

using namespace std;

namespace OHOS {
    void DepacketizeHeaderTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < Communication::SoftBus::MAX_STREAM_LEN - OVERHEAD_LEN)) {
            return;
        }
        char tmp[Communication::SoftBus::MAX_STREAM_LEN - OVERHEAD_LEN + 1] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, sizeof(tmp) - 1) != EOK) {
            return;
        }

        Communication::SoftBus::StreamDepacketizer decode(1);
        decode.DepacketizeHeader((const char *)tmp);
    }

    void DepacketizeBufferTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < Communication::SoftBus::MAX_STREAM_LEN - OVERHEAD_LEN)) {
            return;
        }
        char tmp[Communication::SoftBus::MAX_STREAM_LEN - OVERHEAD_LEN + 1] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, sizeof(tmp) - 1) != EOK) {
            return;
        }

        Communication::SoftBus::StreamDepacketizer decode(1);
        decode.DepacketizeBuffer((char *)tmp, sizeof(tmp));
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DepacketizeHeaderTest(data, size);
    OHOS::DepacketizeBufferTest(data, size);
    return 0;
}
