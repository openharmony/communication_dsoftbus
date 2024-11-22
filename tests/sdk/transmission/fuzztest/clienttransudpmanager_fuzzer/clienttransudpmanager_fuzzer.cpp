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

#include "clienttransudpmanager_fuzzer.h"

#include <securec.h>

#include "session.h"
#include "client_trans_udp_manager.h"
#include "softbus_adapter_mem.h"

#define STR_LEN 100000
#define TEST_TMP_STR_LEN 50
#define TEST_TMP_STR "testtmpStr"
namespace OHOS {
    void TransOnUdpChannelOpenedTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        ChannelInfo channel = {0};
        channel.channelType = CHANNEL_TYPE_UDP;
        channel.businessType = BUSINESS_TYPE_STREAM;
        int32_t udpPort = *(reinterpret_cast<const int32_t *>(data));
        TransOnUdpChannelOpened((char *)data, &channel, &udpPort);
    }

    void TransOnUdpChannelOpenFailedTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
        int32_t errCode = *(reinterpret_cast<const int32_t *>(data));
        TransOnUdpChannelOpenFailed(channelId, errCode);
    }

    void TransOnUdpChannelClosedTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
        TransOnUdpChannelClosed(channelId, SHUTDOWN_REASON_UNKNOWN);
    }

    void TransOnUdpChannelQosEventTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
        int32_t eventId = *(reinterpret_cast<const int32_t *>(data));
        int32_t tvCount = *(reinterpret_cast<const int32_t *>(data));
        QosTv tvList;
        TransOnUdpChannelQosEvent(channelId, eventId, tvCount, &tvList);
    }

    void ClientTransCloseUdpChannelTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
        ClientTransCloseUdpChannel(channelId, SHUTDOWN_REASON_UNKNOWN);
    }

    void TransUdpChannelSendStreamTest(const uint8_t* data, size_t size)
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
        TransUdpChannelSendStream(channelId, &streamdata, &ext, &param);
        SoftBusFree(ptr);
    }

    void TransUdpChannelSendFileTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        const char *sfileList[] = {
            "/data/big.tar",
            "/data/richu.jpg",
            "/data/richu-002.jpg",
            "/data/richu-003.jpg",
        };
        int32_t channelId = *(reinterpret_cast<const int32_t *>(data));
        int32_t fileCnt = *(reinterpret_cast<const int32_t *>(data));
        TransUdpChannelSendFile(channelId, sfileList, NULL, fileCnt);
    }

    void TransGetUdpChannelByFileIdTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        int32_t dfileId = *(reinterpret_cast<const int32_t *>(data));
        UdpChannel udpChannel;
        TransGetUdpChannelByFileId(dfileId, &udpChannel);
    }

    void TransUdpDeleteFileListenerlTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < SESSION_NAME_SIZE_MAX) {
            return;
        }
        char tmp[SESSION_NAME_SIZE_MAX + 1] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, sizeof(tmp) - 1) != EOK) {
            return;
        }
        TransUdpDeleteFileListener(tmp);
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::TransOnUdpChannelOpenedTest(data, size);
    OHOS::TransOnUdpChannelOpenFailedTest(data, size);
    OHOS::TransOnUdpChannelClosedTest(data, size);
    OHOS::TransOnUdpChannelQosEventTest(data, size);
    OHOS::ClientTransCloseUdpChannelTest(data, size);
    OHOS::TransUdpChannelSendStreamTest(data, size);
    OHOS::TransUdpChannelSendFileTest(data, size);
    OHOS::TransGetUdpChannelByFileIdTest(data, size);
    OHOS::TransUdpDeleteFileListenerlTest(data, size);
    return 0;
}
