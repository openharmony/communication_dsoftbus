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
#include "softbus_adapter_mem.h"
#include "softbus_def.h"

namespace OHOS {
    void SendVtpStreamTest(const uint8_t* data, size_t size)
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

        SendVtpStream(channelId, &streamdata, &ext, &param);
        SoftBusFree(ptr);
    }

    void StartVtpStreamChannelServerTest(const uint8_t* data, size_t size)
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
        VtpStreamOpenParam param  = {
            .pkgName = reinterpret_cast<const char *>(ptr),
            .myIp = const_cast<char *>(reinterpret_cast<const char *>(ptr)),
            .peerIp = const_cast<char *>(reinterpret_cast<const char *>(ptr)),
            .peerPort = *(reinterpret_cast<const int32_t *>(ptr)),
            .type = *(reinterpret_cast<const StreamType *>(ptr)),
            .sessionKey = const_cast<uint8_t *>(ptr),
            .keyLen = *(reinterpret_cast<const uint32_t *>(ptr)),
            .isRawStreamEncrypt = size % 2,
        };
        IStreamListener *callback = nullptr;

        StartVtpStreamChannelServer(channelId, &param, callback);
        SoftBusFree(ptr);
    }

    void StartVtpStreamChannelClientTest(const uint8_t* data, size_t size)
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
        VtpStreamOpenParam param  = {
            .pkgName = reinterpret_cast<const char *>(ptr),
            .myIp = const_cast<char *>(reinterpret_cast<const char *>(ptr)),
            .peerIp = const_cast<char *>(reinterpret_cast<const char *>(ptr)),
            .peerPort = *(reinterpret_cast<const int32_t *>(ptr)),
            .type = *(reinterpret_cast<const StreamType *>(ptr)),
            .sessionKey = const_cast<uint8_t *>(ptr),
            .keyLen = *(reinterpret_cast<const uint32_t *>(ptr)),
            .isRawStreamEncrypt = size % 2,
        };
        IStreamListener *callback = nullptr;

        StartVtpStreamChannelClient(channelId, &param, callback);
        SoftBusFree(ptr);
    }

    void CloseVtpStreamChannelTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < PKG_NAME_SIZE_MAX) {
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
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SendVtpStreamTest(data, size);
    OHOS::StartVtpStreamChannelServerTest(data, size);
    OHOS::StartVtpStreamChannelClientTest(data, size);
    return 0;
}
