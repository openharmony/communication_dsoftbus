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

#include "fuzz_data_generator.h"
#include "vtp_stream_socket.h"
#include "stream_common.h"
#include "stream_common_data.h"

namespace OHOS {
    Communication::SoftBus::VtpStreamSocket vtpStreamSocket;

    void VtpCreateClientTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }

        int32_t streamType = *(reinterpret_cast<const int32_t *>(data));
        Communication::SoftBus::IpAndPort ipPort;
        std::pair<uint8_t*, uint32_t> sessionKey = std::make_pair(nullptr, 0);

        vtpStreamSocket.CreateClient(ipPort, streamType, sessionKey);
        vtpStreamSocket.CreateClient(ipPort, ipPort, streamType, sessionKey);
    }

    void VtpCreateServerTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }

        int32_t streamType = *(reinterpret_cast<const int32_t *>(data));
        Communication::SoftBus::IpAndPort ipPort;
        std::pair<uint8_t*, uint32_t> sessionKey = std::make_pair(nullptr, 0);

        vtpStreamSocket.CreateServer(ipPort, streamType, sessionKey);
    }

    void VtpDestroyStreamSocketTest(const uint8_t* data, size_t size)
    {
        (void)data;
        (void)size;

        vtpStreamSocket.DestroyStreamSocket();
    }

    void VtpConnectTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }

        Communication::SoftBus::IpAndPort ipPort;
        ipPort.ip = {0};
        ipPort.port = *(reinterpret_cast<const int32_t *>(data));
        vtpStreamSocket.Connect(ipPort);
    }

    void VtpSetOptionTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }

        int32_t type = *(reinterpret_cast<const int32_t *>(data));
        Communication::SoftBus::StreamAttr tmp;

        vtpStreamSocket.SetOption(type, tmp);
    }

    void VtpGetOptionTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int32_t)) {
            return;
        }

        int32_t type = *(reinterpret_cast<const int32_t *>(data));

        vtpStreamSocket.GetOption(type);
    }

    void VtpSetStreamListenerTest(const uint8_t* data, size_t size)
    {
        (void)data;
        (void)size;

        std::shared_ptr<Communication::SoftBus::IStreamSocketListener> receiver = nullptr;

        vtpStreamSocket.SetStreamListener(receiver);
    }

    void VtpGetEncryptOverheadTest(const uint8_t* data, size_t size)
    {
        (void)data;
        (void)size;

        vtpStreamSocket.GetEncryptOverhead();
    }

    void VtpEncrypt(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(size_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int64_t inlen = 0;
        int64_t outlen = 0;
        GenerateInt64(inlen);
        GenerateInt64(outlen);
        const void *in = reinterpret_cast<const void *>(data + 1);
        void *out = const_cast<void *>(reinterpret_cast<const void *>(data));

        vtpStreamSocket.Encrypt(in, inlen, out, outlen);
        DataGenerator::Clear();
    }

    void VtpDecrypt(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(size_t)) {
            return;
        }
        DataGenerator::Write(data, size);
        int64_t inlen = 0;
        int64_t outlen = 0;
        GenerateInt64(inlen);
        GenerateInt64(outlen);
        const void *in = reinterpret_cast<const void *>(data + 1);
        void *out = const_cast<void *>(reinterpret_cast<const void *>(data));

        vtpStreamSocket.Decrypt(in, inlen, out, outlen);
        DataGenerator::Clear();
    }
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
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
