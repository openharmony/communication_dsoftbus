/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <securec.h>

#include "socket.h"

namespace OHOS {
void ServiceSocketTest(FuzzedDataProvider &provider)
{
#define NETWORK_ID_BUF_LEN 65
    std::string providerNetworkId = provider.ConsumeBytesAsString(NETWORK_ID_BUF_LEN - 1);
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN, providerNetworkId.c_str()) != EOK) {
        return;
    }
    ServiceSocketInfo info = {
        .peerNetworkId = const_cast<char *>(networkId),
        .serviceId = provider.ConsumeIntegral<int64_t>(),
        .peerServiceId = provider.ConsumeIntegral<int64_t>(),
        .dataType =
            static_cast<TransDataType>(provider.ConsumeIntegralInRange<uint16_t>(DATA_TYPE_MESSAGE, DATA_TYPE_BUTT)),
    };

    (void)ServiceSocket(info);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::ServiceSocketTest(provider);
    return 0;
}
