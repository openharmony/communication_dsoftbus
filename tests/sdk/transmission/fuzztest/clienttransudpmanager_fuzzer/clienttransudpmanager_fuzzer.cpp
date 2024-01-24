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

#define STR_LEN 100000
#define TEST_TMP_STR_LEN 50
#define TEST_TMP_STR "testtmpStr"
namespace OHOS {
    void TransOnUdpChannelOpenedTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        ChannelInfo channel = {0};
        channel.channelType = CHANNEL_TYPE_UDP;
        channel.businessType = BUSINESS_TYPE_STREAM;
        int32_t udpPort = size;
        TransOnUdpChannelOpened((char *)data, &channel, &udpPort);
    }

    void TransOnUdpChannelOpenFailedTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        TransOnUdpChannelOpenFailed((int32_t)size, (int32_t)size);
    }

    void TransOnUdpChannelClosedTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        TransOnUdpChannelClosed((int32_t)size, SHUTDOWN_REASON_UNKNOWN);
    }

    void TransOnUdpChannelQosEventTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        QosTv tvList;
        TransOnUdpChannelQosEvent((int32_t)size, (int32_t)size, (int32_t)size, &tvList);
    }

    void ClientTransCloseUdpChannelTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        ClientTransCloseUdpChannel((int32_t)size, SHUTDOWN_REASON_UNKNOWN);
    }

    void TransUdpChannelSendStreamTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        char sendStringData[STR_LEN] = {0};
        StreamData streamdata1 = {
            sendStringData,
            100000,
        };
        char str[TEST_TMP_STR_LEN] = TEST_TMP_STR;
        StreamData streamdata2 = {
            str,
            10,
        };
        StreamFrameInfo ext = {};
        TransUdpChannelSendStream((int32_t)size, &streamdata1, &streamdata2, &ext);
    }

    void TransUdpChannelSendFileTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        const char *sfileList[] = {
            "/data/big.tar",
            "/data/richu.jpg",
            "/data/richu-002.jpg",
            "/data/richu-003.jpg",
        };
        TransUdpChannelSendFile((int32_t)size, sfileList, NULL, (uint32_t)size);
    }

    void TransGetUdpChannelByFileIdTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        UdpChannel udpChannel;
        TransGetUdpChannelByFileId((int32_t)size, &udpChannel);
    }

    void TransUdpDeleteFileListenerlTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < SESSION_NAME_SIZE_MAX)) {
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
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
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
