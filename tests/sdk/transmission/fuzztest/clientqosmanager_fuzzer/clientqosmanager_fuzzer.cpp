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

#include "clientqosmanager_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include "client_qos_manager.h"
#include "trans_server_proxy.h"

namespace OHOS {
void ClientQosReportTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    int32_t channelId = *(reinterpret_cast<const int32_t*>(data));
    int32_t chanType = *(reinterpret_cast<const int32_t*>(data));
    int32_t appType = *(reinterpret_cast<const int32_t*>(data));
    int32_t quality = *(reinterpret_cast<const int32_t*>(data));

    ClientQosReport(channelId, chanType, appType, quality);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ClientQosReportTest(data, size);
    return 0;
}
