/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "socket_fuzzer.h"

#include <string>

#include "fuzz_data_generator.h"
#include "socket.h"

namespace OHOS {
void SocketTestWithNetworkId(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    DataGenerator::Write(data, size);
    uint32_t bufSize = 1;
    (void)GenerateUint32(bufSize);

    std::string socketNetworkId(bufSize, '\0');
    if (!GenerateString(socketNetworkId)) {
        DataGenerator::Clear();
        return;
    }
    DataGenerator::Clear();

    SocketInfo info = {
        .name = const_cast<char *>(DEFAULT_SOCKET_NAME),
        .peerName = const_cast<char *>(DEFAULT_SOCKET_PEER_NAME),
        .peerNetworkId = const_cast<char *>(socketNetworkId.c_str()),
        .pkgName = const_cast<char *>(DEFAULT_SOCKET_PKG_NAME),
        .dataType = DATA_TYPE_MESSAGE,
    };

    (void)Socket(info);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::SocketTestWithNetworkId(data, size);
    return 0;
}
