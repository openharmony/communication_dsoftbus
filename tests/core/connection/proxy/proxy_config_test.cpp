/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include <gtest/gtest.h>

#include <proxy_config.h>

using namespace testing::ext;

class ProxyConfigTest : public testing::Test {
public:
    static void SetUpTestCase() { }
    static void TearDownTestCase() { }
    void SetUp() override { }
    void TearDown() override { }
};

/**
 * @tc.name: ProxyConfigPolicyIsActive
 * @tc.desc: ProxyConfigPolicyIsActive, test policy is active or not
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, ProxyConfigPolicyIsActive, TestSize.Level1)
{
    auto active = ProxyConfigPolicyIsActive(nullptr);
    EXPECT_FALSE(active);

    struct ProxyConfigPolicy configPolicy {};
    active = ProxyConfigPolicyIsActive(&configPolicy);
    EXPECT_FALSE(active);

    configPolicy.active = true;
    active = ProxyConfigPolicyIsActive(&configPolicy);
    EXPECT_FALSE(active);

    configPolicy.active = false;
    configPolicy.Match = [](const struct ProxyConfigPolicy *policy, const ProxyConnectInfo *info) {
        (void)policy;
        (void)info;
        return true;
    };
    active = ProxyConfigPolicyIsActive(&configPolicy);
    EXPECT_FALSE(active);

    configPolicy.active = true;
    active = ProxyConfigPolicyIsActive(&configPolicy);
    EXPECT_FALSE(active);

    configPolicy.active = false;
    configPolicy.Execute = [](const struct ProxyConfigPolicy *policy, const ProxyConnectInfo *info) {
        (void)policy;
        (void)info;
        return static_cast<uint64_t>(0);
    };
    active = ProxyConfigPolicyIsActive(&configPolicy);
    EXPECT_FALSE(active);

    configPolicy.active = true;
    active = ProxyConfigPolicyIsActive(&configPolicy);
    EXPECT_TRUE(active);
}

/**
 * @tc.name: GetProxyConfigManager
 * @tc.desc: GetProxyConfigManager, test global unique manager instance getter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, GetProxyConfigManager, TestSize.Level1)
{
    auto mgr = GetProxyConfigManager();
    ASSERT_NE(mgr, nullptr);

    int counter = 0;
    for (size_t i = 0; i < std::size(mgr->policies); i++) {
        bool active = ProxyConfigPolicyIsActive(&mgr->policies[i]);
        counter += (active ? 1 : 0);
    }
    ASSERT_GT(counter, 0);
}

using ExpectFunction =
    std::function<void(const std::string &describe, const ProxyConfig &got, bool retryable, uint64_t delayMs)>;

static void TestPolicy(const std::string &describe, ProxyConnectInfo &info, const std::vector<uint64_t> &wantTimeoutMs,
    ExpectFunction &&expectFunction)
{
    for (size_t i = 0; i < std::size(wantTimeoutMs); i++) {
        auto config = ProxyGetRetryConfig(GetProxyConfigManager(), &info);
        expectFunction(describe + ": " + std::to_string(i), config, true, wantTimeoutMs[i]);
        info.innerRetryNum += 1;
    }
    auto config = ProxyGetRetryConfig(GetProxyConfigManager(), &info);
    expectFunction(describe + ": out-bound", config, false, 0);
}

/**
 * @tc.name: ProxyGetRetryConfig
 * @tc.desc: ProxyGetRetryConfig, test retry config.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, ProxyGetRetryConfig, TestSize.Level1)
{
    auto expectFunction = [](const std::string &describe, const ProxyConfig &got, bool retryable, uint64_t delayMs) {
        if (got.retryable != retryable) {
            ADD_FAILURE() << describe << ", retryable is unexpected, want=" << retryable << ", got=" << got.retryable;
        }
        if (got.delayMs != delayMs) {
            ADD_FAILURE() << describe << ", timeout is unexpected, want=" << delayMs << ", got=" << got.delayMs;
        }
    };

    auto config = ProxyGetRetryConfig(nullptr, nullptr);
    expectFunction("mgr info nullptr", config, false, 0);

    config = ProxyGetRetryConfig(GetProxyConfigManager(), nullptr);
    expectFunction("info nullptr", config, false, 0);

    ProxyConnectInfo info = { .innerRetryNum = PROXY_RETRY_MAX_TIMES };
    config = ProxyGetRetryConfig(GetProxyConfigManager(), &info);
    expectFunction("get config exceed limited times", config, false, 0);

    info.isAclConnected = true;
    info.innerRetryNum = 0;
    const std::vector<uint64_t> backupOffWant = { 0, 1000, 2000, 4000, 8000, 16000, 32000 };
    TestPolicy("acl connected backoff", info, backupOffWant, expectFunction);

    info.isAclConnected = false;
    info.innerRetryNum = 0;
    const std::vector<uint64_t> unconditionWant = { 15000, 15000, 15000, 15000, 15000, 15000, 15000, 15000, 15000,
        15000, 120000, 120000, 120000, 120000, 120000 };
    TestPolicy("acl disconnected uncondition", info, unconditionWant, expectFunction);
}