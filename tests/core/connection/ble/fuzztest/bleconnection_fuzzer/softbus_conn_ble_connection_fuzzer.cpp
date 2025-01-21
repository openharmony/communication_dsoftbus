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

#include "softbus_conn_ble_connection_fuzzer.h"

#include <vector>
#include <securec.h>
#include <pthread.h>
#include <cstddef>
#include <string>

#include "comm_log.h"
#include "softbus_json_utils.h"
#include "softbus_adapter_mem.h"
#include "softbus_conn_ble_connection.h"

namespace OHOS {
const uint8_t *g_baseFuzzData = nullptr;
size_t g_baseFuzzSize = 0;
size_t g_baseFuzzPos;

template <class T> T GetData()
{
    T objetct{};
    size_t objetctSize = sizeof(objetct);
    if (g_baseFuzzData == nullptr || objetctSize > g_baseFuzzSize - g_baseFuzzPos) {
        COMM_LOGE(COMM_TEST, "data Invalid");
        return objetct;
    }
    errno_t ret = memcpy_s(&objetct, objetctSize, g_baseFuzzData + g_baseFuzzPos, objetctSize);
    if (ret != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy err");
        return {};
    }
    g_baseFuzzPos += objetctSize;
    return objetct;
}

void BleOnDataReceivedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        COMM_LOGE(COMM_TEST, "Invalid param");
        return;
    }
    ConnBleServerEventListener eventListener;
    g_baseFuzzSize = size;
    g_baseFuzzData = data;
    g_baseFuzzPos = 0;

    uint32_t connectionId = GetData<uint32_t>();
    bool isConnCharacterisic = GetData<bool>();
    uint8_t *buf = (uint8_t *)SoftBusCalloc(size * sizeof(uint8_t));
    if (buf == nullptr) {
        COMM_LOGE(COMM_TEST, "calloc faild");
        return;
    }
    if (memcpy_s(buf, size, data, size) != EOK) {
        COMM_LOGE(COMM_TEST, "memcpy err");
        SoftBusFree(buf);
        return;
    }
    eventListener.onServerDataReceived(connectionId, isConnCharacterisic, buf, size);
    return;
}

}
/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::BleOnDataReceivedFuzzTest(data, size);
    return 0;
}