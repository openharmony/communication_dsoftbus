/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "softbussocketrecv_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>

#include "comm_log.h"
#include "fuzz_data_generator.h"
#include "softbus_adapter_socket.h"
#include "softbus_adapter_define.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
const int32_t PROTOCOL_MAXLEN = 100;

struct SocketProtocol {
    unsigned int cmd;
    char data[PROTOCOL_MAXLEN];
};

void SoftBusSocketRecvFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        COMM_LOGE(COMM_TEST, "Invalid param");
        return;
    }

    struct SocketProtocol buf;
    memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
    int32_t socketFd = 0;
    uint32_t len = 0;
    int32_t flags = 0;
    DataGenerator::Write(data, size);
    GenerateInt32(socketFd);
    GenerateUint32(len);
    GenerateInt32(flags);
    DataGenerator::Clear();
    SoftBusSocketRecv(socketFd, &buf, len, flags);
    return;
}

void SoftBusSocketRecvFromFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        COMM_LOGE(COMM_TEST, "Invalid param");
        return;
    }

    struct SocketProtocol buf;
    memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
    int32_t socketFd = 0;
    uint32_t len = 0;
    int32_t flags = 0;
    DataGenerator::Write(data, size);
    GenerateInt32(socketFd);
    GenerateUint32(len);
    GenerateInt32(flags);
    DataGenerator::Clear();
    SoftBusSockAddr  fromAddr;
    memset_s(&fromAddr, sizeof(SoftBusSockAddr), 0, sizeof(SoftBusSockAddr));
    int32_t fromAddrLen;
    SoftBusSocketRecvFrom(socketFd, &buf, len, flags, &fromAddr, &fromAddrLen);
    return;
}

void SoftBusSocketSendFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        COMM_LOGE(COMM_TEST, "Invalid param");
        return;
    }

    uint8_t *buf = static_cast<uint8_t*>(SoftBusCalloc(size * sizeof(uint8_t)));
    if (buf == nullptr) {
        COMM_LOGE(COMM_TEST, "calloc faild");
        return;
    }
    if (memcpy_s(buf, size, data, size) != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy err");
        SoftBusFree(buf);
        return;
    }
    uint32_t len = size;
    int32_t socketFd = 0;
    int32_t flags = 0;
    DataGenerator::Write(data, size);
    GenerateInt32(socketFd);
    GenerateInt32(flags);
    DataGenerator::Clear();

    SoftBusSocketSend(socketFd, buf, len, flags);
    SoftBusFree(buf);
    return;
}

void SoftBusSocketSendToFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(SoftBusSockAddr)) {
        COMM_LOGE(COMM_TEST, "Invalid param");
        return;
    }

    uint8_t *buf = static_cast<uint8_t*>(SoftBusCalloc(size * sizeof(uint8_t)));
    if (buf == nullptr) {
        COMM_LOGE(COMM_TEST, "calloc faild");
        return;
    }
    if (memcpy_s(buf, size, data, size) != EOK) {
        SoftBusFree(buf);
        return;
    }
    uint32_t len = size;
    int32_t socketFd = 0;
    int32_t flags = 0;
    int32_t toAddrLen = 0;
    DataGenerator::Write(data, size);
    GenerateInt32(socketFd);
    GenerateInt32(flags);
    GenerateInt32(toAddrLen);
    DataGenerator::Clear();
    SoftBusSockAddr toAddr = {0};
    if (memcpy_s(&toAddr, sizeof(SoftBusSockAddr), data, sizeof(SoftBusSockAddr)) != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy err");
        SoftBusFree(buf);
        return;
    }
    SoftBusSocketSendTo(socketFd, buf, len, flags, &toAddr, toAddrLen);
    SoftBusFree(buf);
    return;
}

}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SoftBusSocketRecvFuzzTest(data, size);
    OHOS::SoftBusSocketRecvFromFuzzTest(data, size);
    OHOS::SoftBusSocketSendFuzzTest(data, size);
    OHOS::SoftBusSocketSendToFuzzTest(data, size);
    return 0;
}