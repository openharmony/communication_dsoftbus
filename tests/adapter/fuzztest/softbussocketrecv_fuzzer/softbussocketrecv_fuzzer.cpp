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
#include "softbus_adapter_socket.h"
#include "softbus_adapter_define.h"
#include <cstddef>
#include <cstdint>
#include <securec.h>

namespace OHOS {
const int PROTOCOL_MAXLEN = 100;

struct SocketProtocol {
    unsigned int cmd;
    char data[PROTOCOL_MAXLEN];
};

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return false;
    }

    int32_t socketFd = *(reinterpret_cast<const int32_t*>(data));
    struct SocketProtocol buf;
    memset_s(&buf, sizeof(struct SocketProtocol), 0, sizeof(struct SocketProtocol));
    uint32_t len = *(reinterpret_cast<const uint32_t*>(data));
    int32_t flags = *(reinterpret_cast<const int32_t*>(data));

    SoftBusSocketRecv(socketFd, &buf, len, flags);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}