/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "discoveryservice_fuzzer.h"

#include <cstddef>
#include <string>
#include "discovery_service.h"

namespace OHOS {
static std::string TEST_PACKAGE_NAME = "TestPackageName";

static void TestPublishSuccess(int publicId) {}
static void TestPublishFail(int publishId, PublishFailReason reason) {}
static IPublishCallback g_publishCallback = {
    .OnPublishSuccess = TestPublishSuccess,
    .OnPublishFail = TestPublishFail,
};

static void TestDeviceFound(const DeviceInfo *device) {}
static void TestDiscoverFailed(int subscribeId, DiscoveryFailReason failReason) {}
static void TestDiscoverySuccess(int subscribeId) {}
static IDiscoveryCallback g_discoveryCallback = {
    .OnDeviceFound = TestDeviceFound,
    .OnDiscoverFailed = TestDiscoverFailed,
    .OnDiscoverySuccess = TestDiscoverySuccess,
};

static PublishInfo g_publishInfo;
static DiscoverMode GenerateMode(uint8_t data)
{
    if (data < UINT8_MAX / 2) {
        return DISCOVER_MODE_ACTIVE;
    }
    return DISCOVER_MODE_PASSIVE;
}

static ExchangeMedium GenerateMedium(uint8_t data)
{
    if (data < UINT8_MAX / MEDIUM_BUTT) {
        return AUTO;
    }
    if (data < UINT8_MAX / MEDIUM_BUTT * 2) {
        return BLE;
    }
    if (data < UINT8_MAX / MEDIUM_BUTT * 3) {
        return COAP;
    }
    if (data < UINT8_MAX / MEDIUM_BUTT * 4) {
        return USB;
    }
    return COAP1;
}

static ExchangeFreq GenerateFreq(uint8_t data)
{
    if (data < UINT8_MAX / FREQ_BUTT) {
        return LOW;
    }
    if (data < UINT8_MAX / FREQ_BUTT * 2) {
        return MID;
    }
    if (data < UINT8_MAX / FREQ_BUTT * 3) {
        return HIGH;
    }
    return SUPER_HIGH;
}

static PublishInfo *GeneratePublishInfo(const uint8_t *data, size_t size)
{
    if (size < sizeof(PublishInfo)) {
        return &g_publishInfo;
    }

    g_publishInfo.publishId = *data++;
    g_publishInfo.mode = GenerateMode(*data++);
    g_publishInfo.medium = GenerateMedium(*data++);
    g_publishInfo.freq = GenerateFreq(*data);

    return &g_publishInfo;
}

static SubscribeInfo g_subscribeInfo;
static SubscribeInfo *GenerateSubscribeInfo(const uint8_t *data, size_t size)
{
    if (size < sizeof(SubscribeInfo)) {
        return &g_subscribeInfo;
    }

    g_subscribeInfo.subscribeId = *data++;
    g_subscribeInfo.mode = GenerateMode(*data++);
    g_subscribeInfo.medium = GenerateMedium(*data++);
    g_subscribeInfo.freq = GenerateFreq(*data++);
    g_subscribeInfo.isSameAccount = *data++;
    g_subscribeInfo.isWakeRemote = *data;

    return &g_subscribeInfo;
}

void DiscoveryServiceTest(const uint8_t* data, size_t size)
{
    PublishService(TEST_PACKAGE_NAME.c_str(), GeneratePublishInfo(data, size), &g_publishCallback);
    UnPublishService(TEST_PACKAGE_NAME.c_str(), *data);
    StartDiscovery(TEST_PACKAGE_NAME.c_str(), GenerateSubscribeInfo(data, size), &g_discoveryCallback);
    StopDiscovery(TEST_PACKAGE_NAME.c_str(), *data);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    OHOS::DiscoveryServiceTest(data, size);
    return 0;
}