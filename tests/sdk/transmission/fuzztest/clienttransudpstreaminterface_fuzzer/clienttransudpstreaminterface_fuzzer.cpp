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

#include "clienttransudpstreaminterface_fuzzer.h"

#include <securec.h>

#include "client_trans_udp_stream_interface.h"
#include "softbus_def.h"

namespace OHOS {
    void SendVtpStreamTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        StreamData *indata = nullptr;
        StreamData *ext = nullptr;
        StreamFrameInfo *param = nullptr;

        SendVtpStream(size, indata, ext, param);
    }

    void StartVtpStreamChannelServerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        VtpStreamOpenParam *param = nullptr;
        IStreamListener *callback = nullptr;

        StartVtpStreamChannelServer(size, param, callback);
    }

    void StartVtpStreamChannelClientTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        VtpStreamOpenParam *param = nullptr;
        IStreamListener *callback = nullptr;

        StartVtpStreamChannelClient(size, param, callback);
    }

    void CloseVtpStreamChannelTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < PKG_NAME_SIZE_MAX)) {
            return;
        }
        char tmp[PKG_NAME_SIZE_MAX + 1] = {0};
        if (memcpy_s(tmp, PKG_NAME_SIZE_MAX, data, PKG_NAME_SIZE_MAX) != EOK) {
            return;
        };

        CloseVtpStreamChannel(size, tmp);
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SendVtpStreamTest(data, size);
    OHOS::StartVtpStreamChannelServerTest(data, size);
    OHOS::StartVtpStreamChannelClientTest(data, size);
    return 0;
}
