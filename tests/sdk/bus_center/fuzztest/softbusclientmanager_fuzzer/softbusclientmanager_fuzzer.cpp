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

#include "softbusclientmanager_fuzzer.h"
#include "client_bus_center_manager.h"
#include <cstddef>

namespace OHOS {
    constexpr size_t THRESHOLD = 10;
    constexpr int32_t OFFSET = 4;
    constexpr uint32_t NINE = 9;
    enum  CmdId {
        CMD_SOFTBUS_ONE,
        CMD_SOFTBUS_TWO,
        CMD_SOFTBUS_THREE,
        CMD_SOFTBUS_FOUR,
        CMD_SOFTBUS_FIVE,
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

    static void SoftbusClientMagSwitch(uint32_t cmd, const uint8_t *rawData)
    {
        void *info = const_cast<void *>(reinterpret_cast<const void *>(rawData));
        int32_t type = *const_cast<int32_t *>(reinterpret_cast<const int32_t *>(rawData));
        cmd = cmd % NINE;
        switch (cmd) {
            case CMD_SOFTBUS_ONE: {
                bool isOnline = true;
                LnnOnNodeOnlineStateChanged("", isOnline, info);
                break;
            }
            case CMD_SOFTBUS_TWO: {
                LnnOnNodeBasicInfoChanged("", info, type);
                break;
            }
            case CMD_SOFTBUS_THREE: {
                LnnOnJoinResult(info, reinterpret_cast<const char *>(rawData), type);
                break;
            }
            case CMD_SOFTBUS_FOUR: {
                LnnOnLeaveResult(reinterpret_cast<const char *>(rawData), type);
                break;
            }
            case CMD_SOFTBUS_FIVE: {
                LnnOnTimeSyncResult(reinterpret_cast<const void *>(info), type);
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

        SoftbusClientMagSwitch(cmd, rawData);

        return true;
    }
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}