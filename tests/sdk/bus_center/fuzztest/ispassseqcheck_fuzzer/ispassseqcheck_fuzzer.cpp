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

#include "fuzz_data_generator.h"
#include "softbus_sequence_verification.h"

using namespace std;

namespace OHOS {
    constexpr size_t THRESHOLD = 10;
    constexpr uint32_t TEST_NUM = 4;
    constexpr int32_t MINSEQ = 2;
    constexpr int32_t BURDEN_MINSEQ = -2;
    constexpr int32_t MAXSEQ = 4;
    constexpr int32_t BURDEN_MAXSEQ = -1;
    SeqVerifyInfo seqInfo;
    enum  CmdId {
        CMD_SOFTBUS_ONE,
        CMD_SOFTBUS_TWO,
        CMD_SOFTBUS_THREE,
        CMD_SOFTBUS_FOUR,
    };

    static void IsPassSeqCheckSwitch()
    {
        uint64_t bit = 0;
        GenerateUint64(bit);
        bit = bit % THRESHOLD;
        uint32_t cmd = 0;
        GenerateUint32(cmd);
        cmd = cmd % TEST_NUM;
        switch (cmd) {
            case CMD_SOFTBUS_ONE: {
                seqInfo.minSeq = MINSEQ;
                seqInfo.maxSeq = MAXSEQ;
                seqInfo.recvBitmap = bit;
                IsPassSeqCheck(&seqInfo, MINSEQ);
                break;
            }
            case CMD_SOFTBUS_TWO: {
                seqInfo.minSeq = MINSEQ;
                seqInfo.maxSeq = BURDEN_MAXSEQ;
                seqInfo.recvBitmap = bit;
                IsPassSeqCheck(&seqInfo, BURDEN_MINSEQ);
                break;
            }
            case CMD_SOFTBUS_THREE: {
                seqInfo.minSeq = BURDEN_MINSEQ;
                seqInfo.maxSeq = MAXSEQ;
                seqInfo.recvBitmap = bit;
                IsPassSeqCheck(&seqInfo, BURDEN_MINSEQ);
                break;
            }
            case CMD_SOFTBUS_FOUR: {
                seqInfo.minSeq = MINSEQ;
                seqInfo.maxSeq = MINSEQ;
                seqInfo.recvBitmap = bit;
                IsPassSeqCheck(&seqInfo, MINSEQ);
                break;
            }
            default:
                break;
        }
    }
} // namespace OHOS

extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }
    DataGenerator::Write(data, size);

    /* Run your code on data */
    OHOS::IsPassSeqCheckSwitch();

    DataGenerator::Clear();
    return 0;
}