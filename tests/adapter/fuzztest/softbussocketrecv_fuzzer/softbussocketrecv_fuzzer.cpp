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
#include "softbus_adapter_socket.h"
#include "softbus_adapter_define.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
const int PROTOCOL_MAXLEN = 100;
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos;


struct SocketProtocol {
    unsigned int cmd;
    char data[PROTOCOL_MAXLEN];
};

template <class T> T GetData()
{
    T objetct{};
    size_t objetctSize = sizeof(objetct);
    if (g_baseFuzzData == nullptr || objetctSize > g_baseFuzzSize - g_baseFuzzPos) {
        COMM_LOGE(COMM_TEST, "data Invalid");
        return objetct;
    }
    errno_t ret = memcpy_s(&objetct, objetctSize, g_baseFuzzData + g_baseFuzzPos, objetctSize);
    if (ret != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy err");
        return {};
    }
    g_baseFuzzPos += objetctSize;
    return objetct;
}

void SoftBusSocketRecvFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        COMM_LOGE(COMM_TEST, "Invalid param");
        return;
    }

    g_baseFuzzSize = size;
    g_baseFuzzData = data;
    g_baseFuzzPos = 0;
    struct SocketProtocol buf;
    memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
    int32_t socketFd = GetData<int32_t>();
    uint32_t len = GetData<uint32_t>();
    int32_t flags = GetData<int32_t>();
    SoftBusSocketRecv(socketFd, &buf, len, flags);
    return;
}

void SoftBusSocketRecvFromFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        COMM_LOGE(COMM_TEST, "Invalid param");
        return;
    }

    g_baseFuzzSize = size;
    g_baseFuzzData = data;
    g_baseFuzzPos = 0;
    struct SocketProtocol buf;
    memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
    int32_t socketFd = GetData<int32_t>();
    uint32_t len = GetData<uint32_t>();
    int32_t flags = GetData<int32_t>();
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

    g_baseFuzzSize = size;
    g_baseFuzzData = data;
    g_baseFuzzPos = 0;
    uint8_t *buf = nullptr;
    buf = (uint8_t *)SoftBusCalloc(size * sizeof(uint8_t));
    if (buf == nullptr) {
        COMM_LOGE(COMM_TEST, "calloc faild");
        return;
    }
    if (memcpy_s(buf, size, data, size) != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy err");
        SoftBusFree(buf);
        return;
    }
    int32_t socketFd = GetData<int32_t>();
    uint32_t len = size;
    int32_t flags = GetData<int32_t>();

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

    g_baseFuzzSize = size;
    g_baseFuzzData = data;
    g_baseFuzzPos = 0;
    uint8_t *buf = nullptr;
    buf = (uint8_t *)SoftBusCalloc(size * sizeof(uint8_t));
    if (buf == nullptr) {
        COMM_LOGE(COMM_TEST, "calloc faild");
        return;
    }
    if (memcpy_s(buf, size, data, size) != EOK) {
        SoftBusFree(buf);
        return;
    }
    int32_t socketFd = GetData<int32_t>();
    uint32_t len = size;
    int32_t flags = GetData<int32_t>();
    SoftBusSockAddr toAddr = {0};
    if (memcpy_s(&toAddr, sizeof(SoftBusSockAddr), data, sizeof(SoftBusSockAddr)) != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy err");
        SoftBusFree(buf);
        return;
    }
    int32_t toAddrLen = GetData<int32_t>();
    SoftBusSocketSendTo(socketFd, buf, len, flags, &toAddr, toAddrLen);
    SoftBusFree(buf);
    return;
}

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SoftBusSocketRecvFuzzTest(data, size);
    OHOS::SoftBusSocketRecvFromFuzzTest(data, size);
    OHOS::SoftBusSocketSendFuzzTest(data, size);
    OHOS::SoftBusSocketSendToFuzzTest(data, size);
    return 0;
}