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

#include "vtpstreamsocket_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "vtp_stream_socket.h"
#include "stream_common.h"
#include "stream_common_data.h"

namespace OHOS {
    Communication::SoftBus::VtpStreamSocket vtpStreamSocket;

    void VtpCreateClientTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int))) {
            return;
        }

        int streamType = *(reinterpret_cast<const int*>(data));
        Communication::SoftBus::IpAndPort ipPort;
        std::pair<uint8_t*, uint32_t> sessionKey = std::make_pair(nullptr, 0);

        vtpStreamSocket.CreateClient(ipPort, streamType, sessionKey);
        vtpStreamSocket.CreateClient(ipPort, ipPort, streamType, sessionKey);
    }

    void VtpCreateServerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int))) {
            return;
        }

        int streamType = *(reinterpret_cast<const int*>(data));
        Communication::SoftBus::IpAndPort ipPort;
        std::pair<uint8_t*, uint32_t> sessionKey = std::make_pair(nullptr, 0);

        vtpStreamSocket.CreateServer(ipPort, streamType, sessionKey);
    }

    void VtpDestroyStreamSocketTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        vtpStreamSocket.DestroyStreamSocket();
    }

    void VtpConnectTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        Communication::SoftBus::IpAndPort ipPort;
        vtpStreamSocket.Connect(ipPort);
    }

    void VtpSetOptionTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int))) {
            return;
        }

        int type = *(reinterpret_cast<const int*>(data));
        Communication::SoftBus::StreamAttr tmp;

        vtpStreamSocket.SetOption(type, tmp);
    }

    void VtpGetOptionTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size < sizeof(int))) {
            return;
        }

        int type = *(reinterpret_cast<const int*>(data));

        vtpStreamSocket.GetOption(type);
    }

    void VtpSetStreamListenerTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        std::shared_ptr<Communication::SoftBus::IStreamSocketListener> receiver = nullptr;

        vtpStreamSocket.SetStreamListener(receiver);
    }

    void VtpGetEncryptOverheadTest(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        vtpStreamSocket.GetEncryptOverhead();
    }

    void VtpEncrypt(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        vtpStreamSocket.Encrypt(nullptr, size, nullptr, size);
    }

    void VtpDecrypt(const uint8_t* data, size_t size)
    {
        if ((data == nullptr) || (size == 0)) {
            return;
        }

        vtpStreamSocket.Decrypt(nullptr, size, nullptr, size);
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::VtpCreateServerTest(data, size);
    OHOS::VtpDestroyStreamSocketTest(data, size);
    OHOS::VtpConnectTest(data, size);
    OHOS::VtpSetOptionTest(data, size);
    OHOS::VtpGetOptionTest(data, size);
    OHOS::VtpSetStreamListenerTest(data, size);
    OHOS::VtpGetEncryptOverheadTest(data, size);
    OHOS::VtpEncrypt(data, size);
    OHOS::VtpDecrypt(data, size);
    return 0;
}
