/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstring>

#include "comm_log.h"
#include "fuzz_data_generator.h"
#include "lnn_sync_info_manager.h"
#include "securec.h"
#include "softbus_common.h"

using namespace std;

namespace OHOS {
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos;

template <class T>
T GetData()
{
    T objetct {};
    size_t objetctSize = sizeof(objetct);
    if (g_baseFuzzData == nullptr || objetctSize > g_baseFuzzSize - g_baseFuzzPos) {
        return objetct;
    }
    errno_t ret = memcpy_s(&objetct, objetctSize, g_baseFuzzData + g_baseFuzzPos, objetctSize);
    if (ret != EOK) {
        return {};
    }
    g_baseFuzzPos += objetctSize;
    return objetct;
}

void LnnSendSyncInfoMsgFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < NETWORK_ID_BUF_LEN) {
        COMM_LOGE(COMM_TEST, "data or size is vaild!");
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    LnnSyncInfoType type = static_cast<LnnSyncInfoType>
    (GetData<int>() % (LNN_INFO_TYPE_COUNT - LNN_INFO_TYPE_CAPABILITY + 1));
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    string outData;
    GenerateString(outData);
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN, outData.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s networkId is failed!");
        return;
    }
    networkId[NETWORK_ID_BUF_LEN - 1] = '\0';
    LnnSyncInfoMsgComplete complete;
    (void)memset_s(&complete, sizeof(LnnSyncInfoMsgComplete), 0, sizeof(LnnSyncInfoMsgComplete));
    LnnSendSyncInfoMsg(type, networkId, data, (uint32_t)size, complete);
}

void LnnSendP2pSyncInfoMsgFuzzTest(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < NETWORK_ID_BUF_LEN) {
        COMM_LOGE(COMM_TEST, "data or size is vaild!");
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    string outData;
    GenerateString(outData);
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN, outData.c_str()) != EOK) {
        COMM_LOGE(COMM_TEST, "strcpy_s networkId is failed!");
        return;
    }
    networkId[NETWORK_ID_BUF_LEN - 1] = '\0';
    uint32_t netCapability = GetData<uint32_t>();
    LnnSendP2pSyncInfoMsg(networkId, netCapability);
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }

    DataGenerator::Write(data, size);

    /* Run your code on data */
    OHOS::LnnSendSyncInfoMsgFuzzTest(data, size);
    OHOS::LnnSendP2pSyncInfoMsgFuzzTest(data, size);

    DataGenerator::Clear();

    return 0;
}
} // namespace OHOS