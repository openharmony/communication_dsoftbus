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

#include "client_trans_stream.h"

namespace OHOS {
    void TransOnstreamChannelOpenedTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        ChannelInfo *channel = nullptr;

        TransOnstreamChannelOpened(channel, (int32_t *)size);
    }

    void TransSendStreamTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        StreamData *streamdata = nullptr;
        StreamData *ext = nullptr;
        StreamFrameInfo *param = nullptr;

        TransSendStream(size, streamdata, ext, param);
    }

    void TransCloseStreamChannelTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        TransCloseStreamChannel(size);
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::TransOnstreamChannelOpenedTest(data, size);
    OHOS::TransSendStreamTest(data, size);
    OHOS::TransCloseStreamChannelTest(data, size);

    return 0;
}
