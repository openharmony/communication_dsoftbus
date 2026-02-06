/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "setnodekeyinfo_fuzzer.h"
#include <cstddef>
#include <securec.h>
#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
    bool SetNodeKeyInfoTest(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size >= INT32_MAX - 1 ||
            size < SERVICE_FIND_CAP_LEN + sizeof(int32_t) + sizeof(uint32_t)) {
            return false;
        }

        int32_t key = NODE_KEY_SERVICE_FIND_CAP_EX;
        char clientName[] = "client_test";
        char networkId[] = "networkid_test";
        uint8_t capacity[SERVICE_FIND_CAP_LEN] = {0};
        uint32_t offset = 0;
        if (memcpy_s(capacity, SERVICE_FIND_CAP_LEN, data, SERVICE_FIND_CAP_LEN) != EOK) {
            return false;
        }
        offset += SERVICE_FIND_CAP_LEN;
        capacity[SERVICE_FIND_CAP_LEN - 1] = '\0';
        key = *reinterpret_cast<const int32_t *>(data + offset);
        offset += sizeof(int32_t);
        uint32_t len = *reinterpret_cast<const uint32_t *>(data + offset);
        offset += sizeof(uint32_t);

        SetAccessTokenPermission("busCenterTest");
        SetNodeKeyInfo(clientName, networkId, (NodeDeviceInfoKeyEx)key, nullptr, len);
        SetNodeKeyInfo(clientName, networkId, (NodeDeviceInfoKeyEx)key, capacity, len);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::SetNodeKeyInfoTest(data, size);
    return 0;
}
