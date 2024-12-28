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

#include "client_trans_udp_manager.h"
#include "fuzz_data_generator.h"
#include "session.h"
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
        DataGenerator::Write(data, size);
        int32_t udpPort = 0;
        GenerateInt32(udpPort);
        TransOnUdpChannelOpened((char *)data, &channel, &udpPort);
        DataGenerator::Clear();
    }

    void TransOnUdpChannelOpenFailedTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        int32_t errCode = 0;
        GenerateInt32(channelId);
        GenerateInt32(errCode);
        TransOnUdpChannelOpenFailed(channelId, errCode);
        DataGenerator::Clear();
    }

    void TransOnUdpChannelClosedTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        GenerateInt32(channelId);
        TransOnUdpChannelClosed(channelId, SHUTDOWN_REASON_UNKNOWN);
        DataGenerator::Clear();
    }

    void TransOnUdpChannelQosEventTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        int32_t eventId = 0;
        int32_t tvCount = 0;
        GenerateInt32(channelId);
        GenerateInt32(eventId);
        GenerateInt32(tvCount);
        QosTv tvList;
        TransOnUdpChannelQosEvent(channelId, eventId, tvCount, &tvList);
        DataGenerator::Clear();
    }

    void ClientTransCloseUdpChannelTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        GenerateInt32(channelId);
        ClientTransCloseUdpChannel(channelId, SHUTDOWN_REASON_UNKNOWN);
        DataGenerator::Clear();
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
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        GenerateInt32(channelId);
        StreamData streamdata = {
            .buf = const_cast<char *>(reinterpret_cast<const char *>(ptr)),
            .bufLen = size,
        };
        StreamData ext = {
            .buf = const_cast<char *>(reinterpret_cast<const char *>(ptr)),
            .bufLen = size,
        };
        TV tv = { 0 };
        GenerateInt32(tv.type);
        GenerateInt64(tv.value);
        StreamFrameInfo param = {
            .tvCount = 1,
            .tvList = &tv,
        };
        GenerateInt32(param.frameType);
        GenerateInt64(param.timeStamp);
        GenerateInt32(param.seqNum);
        GenerateInt32(param.seqSubNum);
        GenerateInt32(param.level);
        GenerateInt32(param.bitMap);
        TransUdpChannelSendStream(channelId, &streamdata, &ext, &param);
        SoftBusFree(ptr);
        DataGenerator::Clear();
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
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        int32_t fileCnt = 0;
        GenerateInt32(channelId);
        GenerateInt32(fileCnt);
        TransUdpChannelSendFile(channelId, sfileList, NULL, fileCnt);
        DataGenerator::Clear();
    }

    void TransGetUdpChannelByFileIdTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t dfileId = 0;
        GenerateInt32(dfileId);
        UdpChannel udpChannel;
        TransGetUdpChannelByFileId(dfileId, &udpChannel);
        DataGenerator::Clear();
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
