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

#include <benchmark/benchmark.h>
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "softbus_bus_center.h"
#include "token_setproc.h"

namespace OHOS {
static int32_t g_subscribeId = 0;
static int32_t g_publishId = 0;
static const char *g_pkgName = "Softbus_Kits";
static bool g_flag = true;
void AddPermission()
{
    if (g_flag) {
        uint64_t tokenId;
        const char *perms[2];
        perms[0] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
        perms[1] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
        NativeTokenInfoParams infoInstance = {
            .dcapsNum = 0,
            .permsNum = 2,
            .aclsNum = 0,
            .dcaps = NULL,
            .perms = perms,
            .acls = NULL,
            .processName = "Softbus_Kits",
            .aplStr = "normal",
        };
        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
        g_flag = false;
    }
}

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
    {
        AddPermission();
    }
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

static int32_t GetSubscribeId(void)
{
    g_subscribeId++;
    return g_subscribeId;
}

static int32_t GetPublishId(void)
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
    .dataLen = strlen("capdata3")
};

static PublishInfo g_pInfo = {
    .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)"capdata4",
    .dataLen = strlen("capdata4")
};

static void TestDeviceFound(const DeviceInfo *device)
{}

static void TestDiscoverResult(int32_t refreshId, RefreshResult reason)
{}

static void TestPublishResult(int32_t publishId, PublishResult reason)
{}

static IRefreshCallback g_refreshCb = {
    .OnDeviceFound = TestDeviceFound,
    .OnDiscoverResult = TestDiscoverResult
};

static IPublishCb g_publishCb = {
    .OnPublishResult = TestPublishResult
};

/**
 * @tc.name: PublishLNNTestCase
 * @tc.desc: PublishService Performance Testing
 * @tc.type: FUNC
 * @tc.require: PublishService normal operation
 */
BENCHMARK_F(DiscoveryTest, PublishLNNTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        g_pInfo.publishId = GetPublishId();
        state.ResumeTiming();
        int32_t ret = PublishLNN(g_pkgName, &g_pInfo, &g_publishCb);
        if (ret != 0) {
            state.SkipWithError("PublishLNNTestCase failed.");
        }
        state.PauseTiming();
        ret = StopPublishLNN(g_pkgName, g_pInfo.publishId);
        if (ret != 0) {
            state.SkipWithError("StopPublishLNNTestCase failed.");
        }
    }
}
BENCHMARK_REGISTER_F(DiscoveryTest, PublishLNNTestCase);

/**
 * @tc.name: StopPublishLNNTestCase
 * @tc.desc: UnPublishService Performance Testing
 * @tc.type: FUNC
 * @tc.require: UnPublishService normal operation
 */
BENCHMARK_F(DiscoveryTest, StopPublishLNNTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        g_pInfo.publishId = GetPublishId();
        state.PauseTiming();
        int32_t ret = PublishLNN(g_pkgName, &g_pInfo, &g_publishCb);
        if (ret != 0) {
            state.SkipWithError("PublishLNNTestCase failed.");
        }
        state.ResumeTiming();
        ret = StopPublishLNN(g_pkgName, g_pInfo.publishId);
        if (ret != 0) {
            state.SkipWithError("StopPublishLNNTestCase failed.");
        }
    }
}
BENCHMARK_REGISTER_F(DiscoveryTest, StopPublishLNNTestCase);

/**
 * @tc.name: RefreshLNNTestCase
 * @tc.desc: StartDiscovery Performance Testing
 * @tc.type: FUNC
 * @tc.require: StartDiscovery normal operation
 */
BENCHMARK_F(DiscoveryTest, RefreshLNNTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        g_sInfo.subscribeId = GetSubscribeId();
        state.ResumeTiming();
        int32_t ret = RefreshLNN(g_pkgName, &g_sInfo, &g_refreshCb);
        if (ret != 0) {
            state.SkipWithError("RefreshLNNTestCase failed.");
        }
        state.PauseTiming();
        ret = StopRefreshLNN(g_pkgName, g_sInfo.subscribeId);
        if (ret != 0) {
            state.SkipWithError("StoptRefreshLNNTestCase failed.");
        }
    }
}
BENCHMARK_REGISTER_F(DiscoveryTest, RefreshLNNTestCase);

/**
 * @tc.name: StoptRefreshLNNTestCase
 * @tc.desc: StoptDiscovery Performance Testing
 * @tc.type: FUNC
 * @tc.require: StoptDiscovery normal operation
 */
BENCHMARK_F(DiscoveryTest, StoptRefreshLNNTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        g_sInfo.subscribeId = GetSubscribeId();
        state.PauseTiming();
        int32_t ret = RefreshLNN(g_pkgName, &g_sInfo, &g_refreshCb);
        if (ret != 0) {
            state.SkipWithError("RefreshLNNTestCase failed.");
        }
        state.ResumeTiming();
        ret = StopRefreshLNN(g_pkgName, g_sInfo.subscribeId);
        if (ret != 0) {
            state.SkipWithError("StoptRefreshLNNTestCase failed.");
        }
    }
}
BENCHMARK_REGISTER_F(DiscoveryTest, StoptRefreshLNNTestCase);
}

// Run the benchmark
BENCHMARK_MAIN();