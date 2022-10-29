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

#include "ispassseqcheck_fuzzer.h"
#include <cstddef>
#include "softbus_sequence_verification.h"

namespace OHOS {
    constexpr size_t THRESHOLD = 10;
    constexpr uint32_t NINE = 9;
    constexpr int32_t MINSEQ = 2;
    constexpr int32_t MAXSEQ = -2;
    constexpr int32_t OFFSET = 4;
    SeqVerifyInfo seqInfo;
    enum  CmdId {
        CMD_SOFTBUS_ONE,
        CMD_SOFTBUS_TWO,
        CMD_SOFTBUS_THREE,
    };

    uint32_t Convert2Uint32(const uint8_t *ptr)
    {
        if (ptr == nullptr) {
            return 0;
        }
        /*
        * Move the 0th digit 24 to the left, the first digit 16 to the left, the second digit 8 to the left,
        * and the third digit no left
        */
        return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
    }

    static void IsPassSeqCheckSwitch(uint32_t cmd, const uint8_t *rawData)
    {
        int32_t seq = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
        uint64_t bit = *const_cast<uint64_t *>(reinterpret_cast<const uint64_t *>(rawData));
        cmd = cmd % NINE;
        switch (cmd) {
            case CMD_SOFTBUS_ONE: {
                seqInfo.minSeq = MINSEQ;
                seqInfo.maxSeq = seq;
                seqInfo.recvBitmap = bit;
                IsPassSeqCheck(&seqInfo, seq);
                break;
            }
            case CMD_SOFTBUS_TWO: {
                seqInfo.minSeq = seq;
                seqInfo.maxSeq = MAXSEQ;
                seqInfo.recvBitmap = bit;
                IsPassSeqCheck(&seqInfo, seq);
                break;
            }
            case CMD_SOFTBUS_THREE: {
                seqInfo.minSeq = seq;
                seqInfo.maxSeq = seq;
                seqInfo.recvBitmap = bit;
                IsPassSeqCheck(&seqInfo, seq);
                break;
            }
            default:
                break;
        }
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
    {
        (void)size;

        if (rawData == nullptr) {
            return false;
        }
        uint32_t cmd = Convert2Uint32(rawData);
        rawData = rawData + OFFSET;

        IsPassSeqCheckSwitch(cmd, rawData);
        return true;
    }
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}