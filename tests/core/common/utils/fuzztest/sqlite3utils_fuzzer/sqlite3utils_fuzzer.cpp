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

#include "sqlite3utils_fuzzer.h"

#include <unistd.h>

#include "sqlite3_utils.h"

namespace OHOS {
constexpr uint8_t PASSWORD1[] = "ef2d127de37b942baad06145e54b0c619a1f22327b2ebbcfbec78f5564afe39d";
constexpr char USER1_ID[] = "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce";
constexpr size_t THRESHOLD = 10;
constexpr int32_t OFFSET = 4;
constexpr int32_t FOUR = 4;
DbContext *ctx = nullptr;
enum CmdId {
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

static void Splite3UtilsSwitch(uint32_t cmd, const uint8_t *rawData, size_t size)
{
    bool isExist = false;
    if (size < sizeof(DbContext)) {
        return;
    }
    ctx = const_cast<DbContext *>(reinterpret_cast<const DbContext *>(rawData));
    OpenDatabase(&ctx);
    cmd = cmd % FOUR;
    switch (cmd) {
        case CMD_SOFTBUS_ONE: {
            CreateTable(ctx, TABLE_TRUSTED_DEV_INFO);
            DeleteTable(ctx, TABLE_TRUSTED_DEV_INFO);
            break;
        }
        case CMD_SOFTBUS_TWO: {
            CheckTableExist(ctx, TABLE_TRUSTED_DEV_INFO, &isExist);
            break;
        }
        case CMD_SOFTBUS_THREE: {
            EncryptedDb(ctx, PASSWORD1, sizeof(PASSWORD1));
            GetRecordNumByKey(
                ctx, TABLE_TRUSTED_DEV_INFO, const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(USER1_ID)));
            break;
        }
        default:
            break;
    }
    CloseDatabase(ctx);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }
    uint32_t cmd = Convert2Uint32(rawData);
    rawData = rawData + OFFSET;
    size = size - OFFSET;

    Splite3UtilsSwitch(cmd, rawData, size);

    return true;
}
} // namespace OHOS

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
