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

#include "clienttranstcpdirectlistener_fuzzer.h"

#include <securec.h>

#include "client_trans_udp_manager.h"
#include "client_trans_tcp_direct_manager.h"
#include "client_trans_tcp_direct_listener.h"
#include "client_trans_tcp_direct_callback.h"
#include "client_trans_session_callback.h"
#include "fuzz_data_generator.h"
#include "session.h"
#include "softbus_error_code.h"

namespace OHOS {
    int32_t TransOnSessionOpened(const char *sessionName, const ChannelInfo *channel, SessionType flag)
    {
        return 0;
    }

    int32_t TransOnSessionClosed(int32_t channelId, int32_t channelType, ShutdownReason reason)
    {
        return 0;
    }

    int32_t TransOnSessionOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
    {
        return 0;
    }

    int32_t TransOnDataReceived(int32_t channelId, int32_t channelType,
        const void *data, uint32_t len, SessionPktType type)
    {
        return 0;
    }

    int32_t TransOnOnStreamRecevied(int32_t channelId, int32_t channelType,
        const StreamData *data, const StreamData *ext, const StreamFrameInfo *param)
    {
        return 0;
    }

    void TransTdcCreateListenerTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t fd = 0;
        GenerateInt32(fd);
        TransTdcCreateListener(fd);
        DataGenerator::Clear();
    }

    void TransTdcStopReadTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t fd = 0;
        GenerateInt32(fd);
        TransTdcStopRead(fd);
        DataGenerator::Clear();
    }

    void TransTdcSendBytesTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        char tmp = *(reinterpret_cast<const char *>(data));
        TransTdcSendBytes(static_cast<int32_t>(size), &tmp, static_cast<uint32_t>(size), false);
    }

    void TransTdcSendMessageTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }
        char tmp = *(reinterpret_cast<const char *>(data));
        TransTdcSendMessage((int32_t)size, &tmp, (uint32_t)size);
    }

    void TransAddDataBufNodeTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        int32_t fd = 0;
        GenerateInt32(channelId);
        GenerateInt32(fd);
        TransAddDataBufNode(channelId, fd);
        DataGenerator::Clear();
    }

    void TransDelDataBufNodeTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        GenerateInt32(channelId);
        TransDelDataBufNode(channelId);
        DataGenerator::Clear();
    }

    void TransTdcRecvDataTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        GenerateInt32(channelId);
        TransTdcRecvData(channelId);
        DataGenerator::Clear();
    }

    void TransTdcGetInfoByIdTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        GenerateInt32(channelId);
        TransTdcGetInfoById(channelId, NULL);
        DataGenerator::Clear();
    }

    void TransTdcGetInfoByIdWithIncSeqTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        GenerateInt32(channelId);
        TransTdcGetInfoIncFdRefById(channelId, NULL, true);
        DataGenerator::Clear();
    }

    void TransTdcGetInfoByFdTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t fd = 0;
        GenerateInt32(fd);
        TransTdcGetInfoByFd(fd, NULL);
        DataGenerator::Clear();
    }

    void TransTdcCloseChannelTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        GenerateInt32(channelId);
        TransTdcCloseChannel(channelId);
        DataGenerator::Clear();
    }

    void ClientTransTdcOnChannelOpenedTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < SESSION_NAME_SIZE_MAX) {
            return;
        }
        char tmp[SESSION_NAME_SIZE_MAX] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, sizeof(tmp) - 1) != EOK) {
            return;
        }
        ClientTransTdcOnChannelOpened(tmp, NULL);
    }

    void TransDisableSessionListenerTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        GenerateInt32(channelId);
        TransDisableSessionListener(channelId);
        DataGenerator::Clear();
    }

    static void ClientFillSessionCallBack(IClientSessionCallBack *cb)
    {
        cb->OnSessionOpened = TransOnSessionOpened;
        cb->OnSessionClosed = TransOnSessionClosed;
        cb->OnSessionOpenFailed = TransOnSessionOpenFailed;
        cb->OnDataReceived = TransOnDataReceived;
        cb->OnStreamReceived = TransOnOnStreamRecevied;
        cb->OnGetSessionId = NULL;
        cb->OnQosEvent = NULL;
    }
    void ClientTransTdcOnSessionOpenedTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < SESSION_NAME_SIZE_MAX) {
            return;
        }
        ChannelInfo channel = {0};
        char tmp[SESSION_NAME_SIZE_MAX] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, sizeof(tmp) - 1) != EOK) {
            return;
        }
        IClientSessionCallBack cb;
        ClientFillSessionCallBack(&cb);
        if (ClientTransTdcSetCallBack(&cb) != SOFTBUS_OK) {
            return;
        }
        ClientTransTdcOnSessionOpened(tmp, &channel);
    }

    void ClientTransTdcOnSessionClosedTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        IClientSessionCallBack cb;
        ClientFillSessionCallBack(&cb);
        if (ClientTransTdcSetCallBack(&cb) != SOFTBUS_OK) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        GenerateInt32(channelId);
        ClientTransTdcOnSessionClosed(channelId, SHUTDOWN_REASON_UNKNOWN);
        DataGenerator::Clear();
    }

    void ClientTransTdcOnSessionOpenFailedTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }
        IClientSessionCallBack cb;
        ClientFillSessionCallBack(&cb);
        if (ClientTransTdcSetCallBack(&cb) != SOFTBUS_OK) {
            return;
        }
        DataGenerator::Write(data, size);
        int32_t channelId = 0;
        int32_t errCode = 0;
        GenerateInt32(channelId);
        GenerateInt32(errCode);
        ClientTransTdcOnSessionOpenFailed(channelId, errCode);
        DataGenerator::Clear();
    }

    void ClientTransTdcOnDataReceivedTest(const uint8_t* data, size_t size)
    {
        #define PROXY_MAX_MESSAGE_LEN (1 * 1024)
        if (data == nullptr || size < PROXY_MAX_MESSAGE_LEN) {
            return;
        }
        char tmp[PROXY_MAX_MESSAGE_LEN] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, sizeof(tmp) - 1) != EOK) {
            return;
        }
        IClientSessionCallBack cb;
        ClientFillSessionCallBack(&cb);
        if (ClientTransTdcSetCallBack(&cb) != SOFTBUS_OK) {
            return;
        }
        ClientTransTdcOnDataReceived((int32_t)size, tmp, sizeof(tmp), TRANS_SESSION_MESSAGE);
    }
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::TransTdcCreateListenerTest(data, size);
    OHOS::TransTdcStopReadTest(data, size);
    OHOS::TransTdcSendBytesTest(data, size);
    OHOS::TransTdcSendMessageTest(data, size);
    OHOS::TransAddDataBufNodeTest(data, size);
    OHOS::TransDelDataBufNodeTest(data, size);
    OHOS::TransTdcRecvDataTest(data, size);
    OHOS::TransTdcGetInfoByIdTest(data, size);
    OHOS::TransTdcGetInfoByIdWithIncSeqTest(data, size);
    OHOS::TransTdcGetInfoByFdTest(data, size);
    OHOS::TransTdcCloseChannelTest(data, size);
    OHOS::ClientTransTdcOnChannelOpenedTest(data, size);
    OHOS::TransDisableSessionListenerTest(data, size);
    OHOS::ClientTransTdcOnSessionOpenedTest(data, size);
    OHOS::ClientTransTdcOnSessionClosedTest(data, size);
    OHOS::ClientTransTdcOnSessionOpenFailedTest(data, size);
    OHOS::ClientTransTdcOnDataReceivedTest(data, size);
    return 0;
}
