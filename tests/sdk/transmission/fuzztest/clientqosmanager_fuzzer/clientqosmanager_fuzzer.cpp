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
#include "fuzz_data_generator.h"
#include "trans_server_proxy.h"

namespace OHOS {
void ClientQosReportTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    DataGenerator::Write(data, size);

    int32_t channelId = 0;
    int32_t chanType = 0;
    int32_t appType = 0;
    int32_t quality = 0;
    GenerateInt32(channelId);
    GenerateInt32(chanType);
    GenerateInt32(appType);
    GenerateInt32(quality);

    ClientQosReport(channelId, chanType, appType, quality);
    DataGenerator::Clear();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ClientQosReportTest(data, size);
    return 0;
}
