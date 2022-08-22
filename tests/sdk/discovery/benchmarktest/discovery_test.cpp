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

#include <benchmark/benchmark.h>
#include "discovery_service.h"

namespace OHOS {
static int g_subscribeId = 0;
static int g_publishId = 0;
static const char *g_pkgName = "Softbus_Kits";

class DiscoveryTest : public benchmark::Fixture {
public:
    DiscoveryTest()
    {
        Iterations(iterations);
        Repetitions(repetitions);
        ReportAggregatesOnly();
    }
    ~DiscoveryTest() override = default;
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(const ::benchmark::State &state) override
    {}
    void TearDown(const ::benchmark::State &state) override
    {}

protected:
    const int32_t repetitions = 3;
    const int32_t iterations = 1000;
};

void DiscoveryTest::SetUpTestCase(void)
{}

void DiscoveryTest::TearDownTestCase(void)
{}

static int GetSubscribeId(void)
{
    g_subscribeId++;
    return g_subscribeId;
}

static int GetPublishId(void)
{
    g_publishId++;
    return g_publishId;
}

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

static PublishInfo g_pInfo = {
    .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata4",
    .dataLen = sizeof("capdata4")
};

static void TestDeviceFound(const DeviceInfo *device)
{}

static void TestDiscoverFailed(int subscribeId, DiscoveryFailReason failReason)
{}

static void TestDiscoverySuccess(int subscribeId)
{}

static void TestPublishSuccess(int publishId)
{}

static void TestPublishFail(int publishId, PublishFailReason reason)
{}

static IDiscoveryCallback g_subscribeCb = {
    .OnDeviceFound = TestDeviceFound,
    .OnDiscoverFailed = TestDiscoverFailed,
    .OnDiscoverySuccess = TestDiscoverySuccess
};

static IPublishCallback g_publishCb = {
    .OnPublishSuccess = TestPublishSuccess,
    .OnPublishFail = TestPublishFail
};

/**
 * @tc.name: PublishServiceTestCase
 * @tc.desc: PublishService Performance Testing
 * @tc.type: FUNC
 * @tc.require: PublishService normal operation
 */
BENCHMARK_F(DiscoveryTest, PublishServiceTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        g_pInfo.publishId = GetPublishId();
        state.ResumeTiming();
        int ret = PublishService(g_pkgName, &g_pInfo, &g_publishCb);
        if (ret != 0) {
            state.SkipWithError("PublishServiceTestCase failed.");
        }
        state.PauseTiming();
        ret = UnPublishService(g_pkgName, g_pInfo.publishId);
    }
}
BENCHMARK_REGISTER_F(DiscoveryTest, PublishServiceTestCase);

/**
 * @tc.name: UnPublishServiceTestCase
 * @tc.desc: UnPublishService Performance Testing
 * @tc.type: FUNC
 * @tc.require: UnPublishService normal operation
 */
BENCHMARK_F(DiscoveryTest, UnPublishServiceTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        g_pInfo.publishId = GetPublishId();
        state.PauseTiming();
        int ret = PublishService(g_pkgName, &g_pInfo, &g_publishCb);
        if (ret != 0) {
            state.SkipWithError("UnPublishServiceTestCase failed.");
        }
        state.ResumeTiming();
        ret = UnPublishService(g_pkgName, g_pInfo.publishId);
        if (ret != 0) {
            state.SkipWithError("UnPublishServiceTestCase failed.");
        }
    }
}
BENCHMARK_REGISTER_F(DiscoveryTest, UnPublishServiceTestCase);

/**
 * @tc.name: StartDiscoveryTestCase
 * @tc.desc: StartDiscovery Performance Testing
 * @tc.type: FUNC
 * @tc.require: StartDiscovery normal operation
 */
BENCHMARK_F(DiscoveryTest, StartDiscoveryTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        g_sInfo.subscribeId = GetSubscribeId();
        state.ResumeTiming();
        int ret = StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
        if (ret != 0) {
            state.SkipWithError("StartDiscoveryTestCase failed.");
        }
        state.PauseTiming();
        ret = StopDiscovery(g_pkgName, g_sInfo.subscribeId);
    }
}
BENCHMARK_REGISTER_F(DiscoveryTest, StartDiscoveryTestCase);

/**
 * @tc.name: StopDiscoveryTestCase
 * @tc.desc: StoptDiscovery Performance Testing
 * @tc.type: FUNC
 * @tc.require: StoptDiscovery normal operation
 */
BENCHMARK_F(DiscoveryTest, StoptDiscoveryTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        g_sInfo.subscribeId = GetSubscribeId();
        state.PauseTiming();
        int ret = StartDiscovery(g_pkgName, &g_sInfo, &g_subscribeCb);
        if (ret != 0) {
            state.SkipWithError("StoptDiscoveryTestCase failed.");
        }
        state.ResumeTiming();
        ret = StopDiscovery(g_pkgName, g_sInfo.subscribeId);
        if (ret != 0) {
            state.SkipWithError("StoptDiscoveryTestCase failed.");
        }
    }
}
BENCHMARK_REGISTER_F(DiscoveryTest, StoptDiscoveryTestCase);
}

// Run the benchmark
BENCHMARK_MAIN();