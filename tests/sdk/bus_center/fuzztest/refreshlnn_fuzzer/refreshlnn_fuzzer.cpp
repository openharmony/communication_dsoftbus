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
#include "refreshlnn_fuzzer.h"
#include <cstddef>
#include <securec.h>
#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
    static const int32_t MAX_SIZE_DISCOVER_MODE = 2;
    static const int32_t MAX_SIZE_EXCHANGE_MEDIUM = MEDIUM_BUTT + 1;
    static const int32_t MAX_SIZE_EXCHANGE_FREQ = FREQ_BUTT + 1 ;
    static const int32_t MAX_SIZE_CAPABILITYMAP = OSD_CAPABILITY_BITMAP + 1;

    static SubscribeInfo g_sInfo = {
        .subscribeId = 1,
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = COAP,
        .freq = MID,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };

    static void TestDeviceFound(const DeviceInfo *device)
    {
        (void)device;
    }

    static void TestDiscoverResult(int32_t refreshId, RefreshResult reason)
    {
        (void)refreshId;
        (void)reason;
    }

    static IRefreshCallback g_refreshCb = {
        .OnDeviceFound = TestDeviceFound,
        .OnDiscoverResult = TestDiscoverResult
    };


    static void GenRanDiscInfo(char* data, size_t size)
    {
        g_sInfo.subscribeId = size;
        g_sInfo.mode = (size % MAX_SIZE_DISCOVER_MODE) ? DISCOVER_MODE_ACTIVE : DISCOVER_MODE_PASSIVE;
        g_sInfo.medium = (ExchangeMedium)(size % MAX_SIZE_EXCHANGE_MEDIUM);
        g_sInfo.freq = (ExchangeFreq)(size % MAX_SIZE_EXCHANGE_FREQ);
        g_sInfo.isSameAccount = (size % MAX_SIZE_DISCOVER_MODE) ? true : false;
        g_sInfo.isWakeRemote = (size % MAX_SIZE_DISCOVER_MODE) ? true : false;
        g_sInfo.capability = g_capabilityMap[(DataBitMap)(size % MAX_SIZE_CAPABILITYMAP)].capability;
        g_sInfo.capabilityData = (unsigned char *)data;
        g_sInfo.dataLen = size;
    }

    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        if (data == nullptr || size == 0) {
            return true;
        }

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
        GenRanDiscInfo(tmp, size);
        int32_t ret = RefreshLNN(reinterpret_cast<const char *>(tmp), &g_sInfo, &g_refreshCb);
        if (ret == SOFTBUS_OK) {
            StopRefreshLNN(reinterpret_cast<const char *>(tmp), g_sInfo.subscribeId);
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

