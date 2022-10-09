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

#include "startdiscovery_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>

#include "discovery_service.h"
#include "softbus_adapter_mem.h"

namespace OHOS {
static int g_subscribeId = 0;

static int GetSubscribeId(void)
{
    g_subscribeId++;
    if (g_subscribeId <= 0) {
        g_subscribeId = 0;
    }

    return g_subscribeId;
}

static void TestDeviceFound(const DeviceInfo *device)
{}

static void TestDiscoverySuccess(int subscribeId)
{}

static void TestDiscoverFailed(int subscribeId, DiscoveryFailReason failReason)
{}

static IDiscoveryCallback g_subscribeCb = {
    .OnDeviceFound = TestDeviceFound,
    .OnDiscoverFailed = TestDiscoverFailed,
    .OnDiscoverySuccess = TestDiscoverySuccess
};

void StartDiscoveryTest(const uint8_t* data, size_t size)
{
    SubscribeInfo testInfo = {
        .subscribeId = GetSubscribeId(),
        .mode = DISCOVER_MODE_PASSIVE,
        .medium = COAP,
        .freq = LOW,
        .isSameAccount = true,
        .isWakeRemote = false,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata3",
        .dataLen = sizeof("capdata3")
    };
 
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    // add trailing '\0'
    uint8_t *pkgName = (uint8_t *)SoftBusCalloc((size + 1) * sizeof(uint8_t));
    if (pkgName == nullptr) {
        return;
    }
    if (memcpy_s(pkgName, size + 1, data, size) != EOK) {
        SoftBusFree(pkgName);
        return;
    }
    StartDiscovery((const char*)pkgName, &testInfo, &g_subscribeCb);
    SoftBusFree(pkgName);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::StartDiscoveryTest(data, size);

    return 0;
}