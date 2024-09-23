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

#include "rawstreamdata_fuzzer.h"
#include "raw_stream_data.h"
#include "securec.h"
#include "stream_common.h"
#include <memory>
#include <cstddef>
#include <cstdint>

using namespace std;

namespace OHOS {
    void InitStreamDataTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < Communication::SoftBus::MAX_STREAM_LEN)) {
            return;
        }
        char *buf = new char[Communication::SoftBus::MAX_STREAM_LEN + 1];
        if (buf == nullptr) {
            return;
        }
        std::unique_ptr<char[]> inputbuf (buf);
        if (memcpy_s(buf, Communication::SoftBus::MAX_STREAM_LEN + 1,
            data, Communication::SoftBus::MAX_STREAM_LEN) != EOK) {
            delete []buf;
            buf = nullptr;
            return;
        }
        char *ext = new char[Communication::SoftBus::MAX_STREAM_LEN + 1];
        if (ext == nullptr) {
            delete []buf;
            buf = nullptr;
            return;
        }
        std::unique_ptr<char[]> inputext (ext);
        if (memcpy_s(ext, Communication::SoftBus::MAX_STREAM_LEN + 1,
            data, Communication::SoftBus::MAX_STREAM_LEN) != EOK) {
            delete []ext;
            delete []buf;
            buf = nullptr;
            ext = nullptr;
            return;
        }

        Communication::SoftBus::RawStreamData rawstreamdata;
        rawstreamdata.InitStreamData(std::move(inputbuf), Communication::SoftBus::MAX_STREAM_LEN + 1,
            std::move(inputext), Communication::SoftBus::MAX_STREAM_LEN + 1);
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::InitStreamDataTest(data, size);
    return 0;
}
