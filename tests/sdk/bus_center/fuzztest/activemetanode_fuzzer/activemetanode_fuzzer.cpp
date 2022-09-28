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
#include "softbus_bus_center.h"
#include "softbus_errcode.h"

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

        int ret = ActiveMetaNode((const char *)data, &meta, metaNodeId);
        if (ret == SOFTBUS_OK) {
            DeactiveMetaNode((const char *)data, metaNodeId);
        }
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}