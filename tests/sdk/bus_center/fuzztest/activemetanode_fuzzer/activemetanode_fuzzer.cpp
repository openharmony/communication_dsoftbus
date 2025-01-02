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

#include "activemetanode_fuzzer.h"
#include <cstddef>
#include <cstring>
#include <securec.h>
#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
    static MetaNodeConfigInfo meta;

    void GenMetaNodeConfig(const uint8_t *data, size_t size)
    {
        memcpy_s(meta.udid, UDID_BUF_LEN, data, size);
        memcpy_s(meta.deviceName, DEVICE_NAME_BUF_LEN, data, size);
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return true;
        }
        GenMetaNodeConfig(data, size);
        char metaNodeId[NETWORK_ID_BUF_LEN] = {0};

        char *tmp = reinterpret_cast<char *>(malloc(size));
        if (tmp == nullptr) {
            return false;
        }
        if (memset_s(tmp, size, '\0', size) != EOK) {
            free(tmp);
            return false;
        }
        if (memcpy_s(tmp, size, data, size - 1) != EOK) {
            free(tmp);
            return false;
        }

        SetAccessTokenPermission("busCenterTest");
        int32_t ret = ActiveMetaNode(reinterpret_cast<const char *>(tmp), &meta, metaNodeId);
        if (ret == SOFTBUS_OK) {
            DeactiveMetaNode(reinterpret_cast<const char *>(tmp), metaNodeId);
        }
        free(tmp);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}