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

#include "lnn_net_builder.h"
#include <cstddef>
#include <cstring>
#include "securec.h"


namespace OHOS {
    const uint8_t *g_baseFuzzData = nullptr;
    size_t g_baseFuzzSize = 0;
    size_t g_baseFuzzPos;

template <class T> T GetData()
{
    T objetct{};
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


void LnnNotifyDiscoveryDeviceFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    g_baseFuzzData = data;
    g_baseFuzzSize = size;
    g_baseFuzzPos = 0;
    bool isNeedConnect = GetData<bool>();
    const ConnectionAddr addr = *const_cast<ConnectionAddr *>(reinterpret_cast<const ConnectionAddr *>(data));
    LnnNotifyDiscoveryDevice(&addr, isNeedConnect);
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::LnnNotifyDiscoveryDeviceFuzzTest(data, size);
    return 0;
}
}