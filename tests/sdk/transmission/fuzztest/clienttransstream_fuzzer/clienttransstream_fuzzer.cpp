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

#include "clienttransstream_fuzzer.h"

#include <securec.h>
#include "client_trans_stream.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
    void TransOnstreamChannelOpenedTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        ChannelInfo *channel = nullptr;
        int32_t streamPort = *(reinterpret_cast<const int32_t *>(data));

        TransOnstreamChannelOpened(channel, &streamPort);
    }

    void TransSendStreamTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int64_t)) {
            return;
        }
        uint8_t *ptr = static_cast<uint8_t *>(SoftBusCalloc(size + 1));
        if (ptr == nullptr) {
            return;
        }
        if (memcpy_s(ptr, size, data, size) != EOK) {
            SoftBusFree(ptr);
            return;
        }
        int32_t channelId = *(reinterpret_cast<const int32_t *>(ptr));
        StreamData streamdata = {
            .buf = const_cast<char *>(reinterpret_cast<const char *>(ptr)),
            .bufLen = size,
        };
        StreamData ext = {
            .buf = const_cast<char *>(reinterpret_cast<const char *>(ptr)),
            .bufLen = size,
        };
        TV tv = {
            .type = *(reinterpret_cast<const int32_t *>(ptr)),
            .value = *(reinterpret_cast<const int64_t *>(ptr)),
        };
        StreamFrameInfo param = {
            .frameType = *(reinterpret_cast<const int32_t *>(ptr)),
            .timeStamp = *(reinterpret_cast<const int32_t *>(ptr)),
            .seqNum = *(reinterpret_cast<const int32_t *>(ptr)),
            .seqSubNum = *(reinterpret_cast<const int32_t *>(ptr)),
            .level = *(reinterpret_cast<const int32_t *>(ptr)),
            .bitMap = *(reinterpret_cast<const int32_t *>(ptr)),
            .tvCount = 1,
            .tvList = &tv,
        };

        TransSendStream(channelId, &streamdata, &ext, &param);
        SoftBusFree(ptr);
    }

    void TransCloseStreamChannelTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        int32_t channelId = *(reinterpret_cast<const int32_t *>(data));

        TransCloseStreamChannel(channelId);
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::TransOnstreamChannelOpenedTest(data, size);
    OHOS::TransSendStreamTest(data, size);
    OHOS::TransCloseStreamChannelTest(data, size);
    return 0;
}
