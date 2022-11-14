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

#include "softbusutils_fuzzer.h"
#include <securec.h>
#include "softbus_utils.h"

namespace OHOS {
    constexpr size_t THRESHOLD = 10;
    constexpr int32_t OFFSET = 4;
    constexpr uint32_t FOUR = 4;
    enum  CmdId {
        CMD_SOFTBUS_ONE,
        CMD_SOFTBUS_TWO,
        CMD_SOFTBUS_THREE,
        CMD_SOFTBUS_FOUR,
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

    static void SoftbusUtilsSwitch(uint32_t cmd, const uint8_t *rawData, size_t size)
    {
        char *tmp = (char *)malloc(size);
        if (tmp == nullptr) {
            return;
        }
        if (memset_s(tmp, size, '\0', size) != EOK) {
            free(tmp);
            return;
        }
        if (memcpy_s(tmp, size, rawData, size - 1) != EOK) {
            free(tmp);
            return;
        }

        cmd = cmd % FOUR;
        switch (cmd) {
            case CMD_SOFTBUS_ONE: {
                char outBuf[] = "\0";
                uint32_t outBufLen = 0;
                ConvertBytesToHexString(outBuf, outBufLen, reinterpret_cast<const unsigned char *>(tmp), size);
                break;
            }
            case CMD_SOFTBUS_TWO: {
                StrCmpIgnoreCase(reinterpret_cast<const char *>(tmp), reinterpret_cast<const char *>(tmp));
                break;
            }
            case CMD_SOFTBUS_THREE: {
                IsValidString(reinterpret_cast<const char *>(tmp), size);
                break;
            }
            default:
                break;
        }
        free(tmp);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
    {
        if (rawData == nullptr || size < THRESHOLD) {
            return false;
        }
        uint32_t cmd = Convert2Uint32(rawData);
        rawData = rawData + OFFSET;
        size = size - OFFSET;
        SoftbusUtilsSwitch(cmd, rawData, size);

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}