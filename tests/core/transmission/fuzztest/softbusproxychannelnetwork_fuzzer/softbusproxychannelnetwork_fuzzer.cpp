/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "softbusproxychannellistener_fuzzer.h"

#include <cstddef>
#include <securec.h>

#include "softbus_transmission_interface.h"

namespace OHOS {
void TransRegisterNetworkingChannelListenerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(INetworkingListener))) {
        return;
    }

    INetworkingListener listener;
    if (memcpy_s(&listener, sizeof(INetworkingListener), data, sizeof(INetworkingListener)) != EOK) {
        return;
    }

    TransRegisterNetworkingChannelListener("", &listener);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::TransRegisterNetworkingChannelListenerTest(data, size);
    return 0;
}
