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
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_type_def.h"

namespace OHOS {
void ClientTransPendingTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint64_t))) {
        return;
    }

    uint32_t id = *(reinterpret_cast<const uint32_t*>(data));
    uint64_t seq = *(reinterpret_cast<const uint64_t*>(data));
    uint32_t waitMillis = *(reinterpret_cast<const uint32_t*>(data));
    bool isDelete = *(reinterpret_cast<const bool*>(data));
    TransPendData pendDate = {0};

    CreatePendingPacket(id, seq);
    DeletePendingPacket(id, seq);
    GetPendingPacketData(id, seq, waitMillis, isDelete, &pendDate);
    SetPendingPacketData(id, seq, &pendDate);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ClientTransPendingTest(data, size);
    return 0;
}
