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

#include "publishservice_fuzzer.h"
#include <cstddef>
#include <cstdint>
#include "discovery_service.h"

namespace OHOS {
static int g_publishId = 0;

static int GetPublishId(void)
{
    g_publishId++;
    if (g_publishId <= 0) {
        g_publishId = 0;
    }

    return g_publishId;
}

static void TestPublishSuccess(int publishId)
{}

static void TestPublishFail(int publishId, PublishFailReason reason)
{}

static IPublishCallback g_publishCb = {
    .OnPublishSuccess = TestPublishSuccess,
    .OnPublishFail = TestPublishFail
};

void PublishServiceTest(const uint8_t* data, size_t size)
{
    PublishInfo testInfo = {
        .publishId = GetPublishId(),
        .mode = DISCOVER_MODE_ACTIVE,
        .medium = AUTO,
        .freq = LOW,
        .capability = "dvKit",
        .capabilityData = (unsigned char *)"capdata2",
        .dataLen = sizeof("capdata2")
    };

    if ((data == nullptr) || (size <= 0)) {
        return;
    }

    PublishService((const char*)data, &testInfo, &g_publishCb);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::PublishServiceTest(data, size);

    return 0;
}