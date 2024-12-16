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

#include "streammsgmanager_fuzzer.h"
#include "stream_msg_manager.h"
#include "common_inner.h"
#include <cstddef>
#include <cstdint>

using namespace std;

namespace OHOS {
    void SendTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int) + sizeof(int) + sizeof(int) + sizeof(int)) {
            return;
        }
        uint32_t offset = 0;
        Communication::SoftBus::HistoryStats stats;
        stats.periodFrameNum = *(reinterpret_cast<const int *>(data));
        offset += sizeof(int);
        stats.avgFrameInterval = *(reinterpret_cast<const int *>(data + offset));
        offset += sizeof(int);
        stats.minFrameInterval = *(reinterpret_cast<const int *>(data + offset));
        offset += sizeof(int);
        stats.maxFrameInterval = *(reinterpret_cast<const int *>(data + offset));

        Communication::SoftBus::StreamMsgManager streamMsgManager;
        streamMsgManager.Send((const Communication::SoftBus::HistoryStats &)stats);
    }

    void RecvTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int) + sizeof(int) + sizeof(int) + sizeof(int)) {
            return;
        }
        uint32_t offset = 0;
        Communication::SoftBus::HistoryStats stats;
        stats.periodFrameNum = *(reinterpret_cast<const int *>(data));
        offset += sizeof(int);
        stats.avgFrameInterval = *(reinterpret_cast<const int *>(data + offset));
        offset += sizeof(int);
        stats.minFrameInterval = *(reinterpret_cast<const int *>(data + offset));
        offset += sizeof(int);
        stats.maxFrameInterval = *(reinterpret_cast<const int *>(data + offset));

        Communication::SoftBus::StreamMsgManager streamMsgManager;
        streamMsgManager.Recv((const Communication::SoftBus::HistoryStats &)stats);
    }

    void UpdateTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size < sizeof(int) + sizeof(int) + sizeof(int) + sizeof(int)) {
            return;
        }
        uint32_t offset = 0;
        Communication::SoftBus::HistoryStats stats;
        stats.periodFrameNum = *(reinterpret_cast<const int *>(data));
        offset += sizeof(int);
        stats.avgFrameInterval = *(reinterpret_cast<const int *>(data + offset));
        offset += sizeof(int);
        stats.minFrameInterval = *(reinterpret_cast<const int *>(data + offset));
        offset += sizeof(int);
        stats.maxFrameInterval = *(reinterpret_cast<const int *>(data + offset));

        Communication::SoftBus::StreamMsgManager streamMsgManager;
        streamMsgManager.Update((const Communication::SoftBus::HistoryStats &)stats);
    }

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SendTest(data, size);
    OHOS::RecvTest(data, size);
    OHOS::UpdateTest(data, size);
    return 0;
}
