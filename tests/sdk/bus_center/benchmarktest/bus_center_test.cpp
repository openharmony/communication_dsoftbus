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
#include <securec.h>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "token_setproc.h"

#define CAPABILITY_3 "capdata3"
#define CAPABILITY_4 "capdata4"

namespace OHOS {
constexpr char TEST_PKG_NAME[] = "com.softbus.test";
static int32_t g_subscribeId = 0;
static int32_t g_publishId = 0;
static bool flag = true;
void AddPermission()
{
    if (flag) {
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
            .processName = "com.softbus.test",
            .aplStr = "normal",
        };
        tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
        OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
        flag = false;
    }
}

class BusCenterTest : public benchmark::Fixture {
public:
    BusCenterTest()
    {
        Iterations(iterations);
        Repetitions(repetitions);
        ReportAggregatesOnly();
    }
    ~BusCenterTest() override = default;
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(const ::benchmark::State &state) override
    {
        AddPermission();
    }

protected:
    const int32_t repetitions = 3;
    const int32_t iterations = 1000;
};

void BusCenterTest::SetUpTestCase(void) { }

void BusCenterTest::TearDownTestCase(void) { }

static void OnNodeOnline(NodeBasicInfo *info)
{
    (void)info;
}

static INodeStateCb g_nodeStateCb = {
    .events = EVENT_NODE_STATE_ONLINE,
    .onNodeOnline = OnNodeOnline,
};

static int32_t GetPublishId(void)
{
    g_publishId++;
    return g_publishId;
}

static PublishInfo g_pInfo = { .publishId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)CAPABILITY_4,
    .dataLen = strlen(CAPABILITY_4) };

static void TestPublishResult(int32_t publishId, PublishResult reason) { }

static IPublishCb g_publishCb = { .OnPublishResult = TestPublishResult };

static int32_t GetSubscribeId(void)
{
    g_subscribeId++;
    return g_subscribeId;
}

static SubscribeInfo g_sInfo = { .subscribeId = 1,
    .mode = DISCOVER_MODE_ACTIVE,
    .medium = COAP,
    .freq = MID,
    .isSameAccount = true,
    .isWakeRemote = false,
    .capability = "dvKit",
    .capabilityData = (unsigned char *)CAPABILITY_3,
    .dataLen = strlen(CAPABILITY_3) };

static void TestDeviceFound(const DeviceInfo *device) { }

static void TestDiscoverResult(int32_t refreshId, RefreshResult reason) { }

static IRefreshCallback g_refreshCb = { .OnDeviceFound = TestDeviceFound, .OnDiscoverResult = TestDiscoverResult };

/**
 * @tc.name: RegNodeDeviceStateCbTestCase
 * @tc.desc: RegNodeDeviceStateCb Performance Testing
 * @tc.type: FUNC
 * @tc.require: RegNodeDeviceStateCb normal operation
 */
BENCHMARK_F(BusCenterTest, RegNodeDeviceStateCbTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        state.ResumeTiming();
        int32_t ret = RegNodeDeviceStateCb(TEST_PKG_NAME, &g_nodeStateCb);
        if (ret != 0) {
            state.SkipWithError("RegNodeDeviceStateCbTestCase failed.");
        }
        state.PauseTiming();
        UnregNodeDeviceStateCb(&g_nodeStateCb);
    }
}
BENCHMARK_REGISTER_F(BusCenterTest, RegNodeDeviceStateCbTestCase);

/**
 * @tc.name: UnregNodeDeviceStateCbTestCase
 * @tc.desc: UnregNodeDeviceStateCb Performance Testing
 * @tc.type: FUNC
 * @tc.require: UnregNodeDeviceStateCb normal operation
 */
BENCHMARK_F(BusCenterTest, UnregNodeDeviceStateCbTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        state.PauseTiming();
        RegNodeDeviceStateCb(TEST_PKG_NAME, &g_nodeStateCb);
        state.ResumeTiming();
        int32_t ret = UnregNodeDeviceStateCb(&g_nodeStateCb);
        if (ret != 0) {
            state.SkipWithError("UnregNodeDeviceStateCbTestCase failed.");
        }
    }
}
BENCHMARK_REGISTER_F(BusCenterTest, UnregNodeDeviceStateCbTestCase);

/**
 * @tc.name: GetAllNodeDeviceInfoTestCase
 * @tc.desc: GetAllNodeDeviceInfo Performance Testing
 * @tc.type: FUNC
 * @tc.require: GetAllNodeDeviceInfo normal operation
 */
BENCHMARK_F(BusCenterTest, GetAllNodeDeviceInfoTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        NodeBasicInfo *info = nullptr;
        int32_t infoNum;

        int32_t ret = GetAllNodeDeviceInfo(TEST_PKG_NAME, &info, &infoNum);
        if (ret != 0) {
            state.SkipWithError("GetAllNodeDeviceInfoTestCase failed.");
        }
        FreeNodeInfo(info);
    }
}
BENCHMARK_REGISTER_F(BusCenterTest, GetAllNodeDeviceInfoTestCase);

/**
 * @tc.name: GetLocalNodeDeviceInfoTestCase
 * @tc.desc: GetLocalNodeDeviceInfo Performance Testing
 * @tc.type: FUNC
 * @tc.require: GetLocalNodeDeviceInfo normal operation
 */
BENCHMARK_F(BusCenterTest, GetLocalNodeDeviceInfoTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        int32_t ret;
        NodeBasicInfo localNode;

        ret = GetLocalNodeDeviceInfo(TEST_PKG_NAME, &localNode);
        if (ret != 0) {
            state.SkipWithError("GetLocalNodeDeviceInfoTestCase failed.");
        }
    }
}
BENCHMARK_REGISTER_F(BusCenterTest, GetLocalNodeDeviceInfoTestCase);

/**
 * @tc.name: GetNodeKeyInfoTestCase
 * @tc.desc: GetNodeKeyInfo Performance Testing
 * @tc.type: FUNC
 * @tc.require: GetNodeKeyInfo normal operation
 */
BENCHMARK_F(BusCenterTest, GetNodeKeyInfoTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        int32_t ret;
        NodeBasicInfo info;
        char udid[UDID_BUF_LEN] = { 0 };
        (void)memset_s(&info, sizeof(NodeBasicInfo), 0, sizeof(NodeBasicInfo));
        state.PauseTiming();
        GetLocalNodeDeviceInfo(TEST_PKG_NAME, &info);
        state.ResumeTiming();
        ret = GetNodeKeyInfo(TEST_PKG_NAME, info.networkId, NODE_KEY_UDID, (uint8_t *)udid, UDID_BUF_LEN);
        if (ret != 0) {
            state.SkipWithError("GetNodeKeyInfoTestCase failed.");
        }
    }
}
BENCHMARK_REGISTER_F(BusCenterTest, GetNodeKeyInfoTestCase);

/**
 * @tc.name: PublishLNNTestCase
 * @tc.desc: PublishLNN Performance Testing
 * @tc.type: FUNC
 * @tc.require: PublishLNN normal operation
 */
BENCHMARK_F(BusCenterTest, PublishLNNTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        int32_t ret;
        g_pInfo.publishId = GetPublishId();
        state.ResumeTiming();
        ret = PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
        if (ret != 0) {
            state.SkipWithError("PublishLNNTestCase failed.");
        }
        state.PauseTiming();
        StopPublishLNN(TEST_PKG_NAME, g_pInfo.publishId);
    }
}
BENCHMARK_REGISTER_F(BusCenterTest, PublishLNNTestCase);

/**
 * @tc.name: StopPublishLNNTestCase
 * @tc.desc: StopPublishLNN Performance Testing
 * @tc.type: FUNC
 * @tc.require: StopPublishLNN normal operation
 */
BENCHMARK_F(BusCenterTest, StopPublishLNNTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        int32_t ret;
        g_pInfo.publishId = GetPublishId();

        state.PauseTiming();
        PublishLNN(TEST_PKG_NAME, &g_pInfo, &g_publishCb);
        state.ResumeTiming();
        ret = StopPublishLNN(TEST_PKG_NAME, g_pInfo.publishId);
        if (ret != 0) {
            state.SkipWithError("StopPublishLNNTestCase failed.");
        }
    }
}
BENCHMARK_REGISTER_F(BusCenterTest, StopPublishLNNTestCase);

/**
 * @tc.name: RefreshLNNTestCase
 * @tc.desc: RefreshLNN Performance Testing
 * @tc.type: FUNC
 * @tc.require: RefreshLNN normal operation
 */
BENCHMARK_F(BusCenterTest, RefreshLNNTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        int32_t ret;
        g_sInfo.subscribeId = GetSubscribeId();

        state.ResumeTiming();
        ret = RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
        if (ret != 0) {
            state.SkipWithError("RefreshLNNTestCase failed.");
        }
        state.PauseTiming();
        StopRefreshLNN(TEST_PKG_NAME, g_sInfo.subscribeId);
    }
}
BENCHMARK_REGISTER_F(BusCenterTest, RefreshLNNTestCase);

/**
 * @tc.name:StopRefreshLNNTestCase
 * @tc.desc: StopRefreshLNN Performance Testing
 * @tc.type: FUNC
 * @tc.require: StopRefreshLNN normal operation
 */
BENCHMARK_F(BusCenterTest, StopRefreshLNNTestCase)(benchmark::State &state)
{
    while (state.KeepRunning()) {
        int32_t ret;
        g_sInfo.subscribeId = GetSubscribeId();

        state.PauseTiming();
        RefreshLNN(TEST_PKG_NAME, &g_sInfo, &g_refreshCb);
        state.ResumeTiming();
        ret = StopRefreshLNN(TEST_PKG_NAME, g_sInfo.subscribeId);
        if (ret != 0) {
            state.SkipWithError("StopRefreshLNNTestCase failed.");
        }
    }
}
BENCHMARK_REGISTER_F(BusCenterTest, StopRefreshLNNTestCase);
} // namespace OHOS

// Run the benchmark
BENCHMARK_MAIN();