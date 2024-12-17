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

#include "clienttranspending_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include <cinttypes>
#include <string>
#include "client_trans_pending.h"
#include "common_list.h"
#include "fuzz_data_generator.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_type_def.h"

namespace OHOS {
void ClientTransPendingTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint64_t))) {
        return;
    }
    DataGenerator::Write(data, size);

    uint32_t id = 0;
    uint64_t seq = 0;
    uint32_t waitMillis = 0;
    bool isDelete = 0;
    TransPendData pendDate = {0};
    GenerateUint32(id);
    GenerateUint64(seq);
    GenerateUint32(waitMillis);
    GenerateBool(isDelete);

    CreatePendingPacket(id, seq);
    DeletePendingPacket(id, seq);
    GetPendingPacketData(id, seq, waitMillis, isDelete, &pendDate);
    SetPendingPacketData(id, seq, &pendDate);
    DataGenerator::Clear();
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ClientTransPendingTest(data, size);
    return 0;
}
