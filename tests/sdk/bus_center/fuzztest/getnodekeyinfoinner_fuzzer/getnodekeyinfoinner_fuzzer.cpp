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

#include "getnodekeyinfoinner_fuzzer.h"
#include <cstddef>
#include <cstring>
#include <securec.h>
#include "softbus_bus_center.h"
#include "client_bus_center_manager.h"
#include "softbus_errcode.h"

namespace OHOS {
    bool GetNodeKeyInfoInnerTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return true;
        }

        NodeDeviceInfoKey key = NODE_KEY_NETWORK_CAPABILITY;
        uint8_t udid[UDID_BUF_LEN] = {0};
        GetNodeKeyInfoInner((const char *)data,
                            const_cast<char *>(reinterpret_cast<const char *>(data)), key, udid, UDID_BUF_LEN);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetNodeKeyInfoInnerTest(data, size);
    return 0;
}
