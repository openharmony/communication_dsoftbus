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

#include "regnodedevicestatecb_fuzzer.h"
#include <cstddef>
#include <securec.h>
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
    static INodeStateCb g_stateCb;

    void onNodeOnline(NodeBasicInfo *info)
    {
        (void)info;
    }
  
    void onNodeOffline(NodeBasicInfo *info)
    {
        (void)info;
    }
   
    void onNodeBasicInfoChanged(NodeBasicInfoType type, NodeBasicInfo *info)
    {
        (void)type;
        (void)info;
    }


    static void GenRanDiscInfo(const uint8_t* data, size_t size)
    {
        (void)data;
        (void)size;
        g_stateCb.events = EVENT_NODE_STATE_ONLINE | EVENT_NODE_STATE_OFFLINE;
        g_stateCb.onNodeOffline = onNodeOffline;
        g_stateCb.onNodeOnline = onNodeOnline;
        g_stateCb.onNodeBasicInfoChanged = onNodeBasicInfoChanged;
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return true;
        }
        GenRanDiscInfo(data, size);
        char tmp[65] = {0};
        if (memcpy_s(tmp, sizeof(tmp) - 1, data, size) != EOK) {
            return true;
        }
        int32_t ret = RegNodeDeviceStateCb((const char *)tmp, &g_stateCb);
        if (ret == SOFTBUS_OK) {
            UnregNodeDeviceStateCb(&g_stateCb);
        }
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

