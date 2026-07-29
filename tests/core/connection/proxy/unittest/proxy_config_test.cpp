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

#include "proxy_config.h"

using namespace testing::ext;

namespace {
void TestPolicy(const std::string &describe, ProxyConnectInfo &info, const std::vector<uint64_t> &wantTimeoutMs)
{
    for (size_t i = 0; i < std::size(wantTimeoutMs); i++) {
        auto config = ProxyGetRetryConfig(GetProxyConfigManager(), &info);
        EXPECT_TRUE(config.retryable) << describe << ": " << i << " should be retryable";
        EXPECT_EQ(config.delayMs, wantTimeoutMs[i]) << describe << ": " << i << " delayMs mismatch";
        info.innerRetryNum += 1;
    }
    auto config = ProxyGetRetryConfig(GetProxyConfigManager(), &info);
    EXPECT_FALSE(config.retryable) << describe << ": out-bound should not be retryable";
    EXPECT_EQ(config.delayMs, 0) << describe << ": out-bound delayMs should be 0";
}
}

class ProxyConfigTest : public testing::Test {};

/**
 * @tc.name: ProxyConfigPolicyIsActive
 * @tc.desc: ProxyConfigPolicyIsActive, test policy is active or not
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, ProxyConfigPolicyIsActive, TestSize.Level1)
{
    // null policy → not active
    auto active = ProxyConfigPolicyIsActive(nullptr);
    EXPECT_FALSE(active);

    // all fields default (active=false, Match=null, Execute=null) → not active
    ProxyConfigPolicy configPolicy {};
    active = ProxyConfigPolicyIsActive(&configPolicy);
    EXPECT_FALSE(active);

    // active=true, Match=null, Execute=null → not active
    configPolicy.active = true;
    active = ProxyConfigPolicyIsActive(&configPolicy);
    EXPECT_FALSE(active);

    // active=false, Match=set, Execute=null → not active
    configPolicy.active = false;
    configPolicy.Match = [](const ProxyConfigPolicy *policy, const ProxyConnectInfo *info) {
        (void)policy;
        (void)info;
        return true;
    };
    active = ProxyConfigPolicyIsActive(&configPolicy);
    EXPECT_FALSE(active);

    // active=true, Match=set, Execute=null → not active
    configPolicy.active = true;
    active = ProxyConfigPolicyIsActive(&configPolicy);
    EXPECT_FALSE(active);

    // active=false, Match=set, Execute=set → not active
    configPolicy.active = false;
    configPolicy.Execute = [](const ProxyConfigPolicy *policy, const ProxyConnectInfo *info) {
        (void)policy;
        (void)info;
        return static_cast<uint64_t>(0);
    };
    active = ProxyConfigPolicyIsActive(&configPolicy);
    EXPECT_FALSE(active);

    // active=true, Match=set, Execute=set → active
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

/**
 * @tc.name: ProxyGetRetryConfig
 * @tc.desc: ProxyGetRetryConfig, test retry config.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, ProxyGetRetryConfig, TestSize.Level1)
{
    // null params → not retryable
    auto config = ProxyGetRetryConfig(nullptr, nullptr);
    EXPECT_FALSE(config.retryable);
    EXPECT_EQ(config.delayMs, 0);

    config = ProxyGetRetryConfig(GetProxyConfigManager(), nullptr);
    EXPECT_FALSE(config.retryable);
    EXPECT_EQ(config.delayMs, 0);

    // exceed max retry times → not retryable
    ProxyConnectInfo info = { .innerRetryNum = PROXY_RETRY_MAX_TIMES };
    config = ProxyGetRetryConfig(GetProxyConfigManager(), &info);
    EXPECT_FALSE(config.retryable);
    EXPECT_EQ(config.delayMs, 0);

    // ACL connected: backoff policy (stage 1)
    info.isAclConnected = true;
    info.innerRetryNum = 0;
    const std::vector<uint64_t> backupOffWant = { 0, 1000, 2000, 4000, 8000, 16000, 32000 };
    TestPolicy("acl connected backoff", info, backupOffWant);

    // ACL disconnected: fixed delay policy (stage 2 + stage 3)
    info.isAclConnected = false;
    info.innerRetryNum = 0;
    const std::vector<uint64_t> unconditionWant = { 15000, 15000, 15000, 15000,
        120000, 120000, 120000, 120000, 120000 };
    TestPolicy("acl disconnected uncondition", info, unconditionWant);
}

/**
 * @tc.name: GetProxyConfigManagerSingleton
 * @tc.desc: test GetProxyConfigManager returns same singleton instance
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, GetProxyConfigManagerSingleton, TestSize.Level1)
{
    auto mgr1 = GetProxyConfigManager();
    auto mgr2 = GetProxyConfigManager();
    ASSERT_NE(mgr1, nullptr);
    EXPECT_EQ(mgr1, mgr2);
}

/**
 * @tc.name: GetProxyConfigManagerPolicyCount
 * @tc.desc: test GetProxyConfigManager has exactly 3 active policies
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, GetProxyConfigManagerPolicyCount, TestSize.Level1)
{
    auto mgr = GetProxyConfigManager();
    ASSERT_NE(mgr, nullptr);

    int activeCount = 0;
    for (size_t i = 0; i < std::size(mgr->policies); i++) {
        if (ProxyConfigPolicyIsActive(&mgr->policies[i])) {
            activeCount++;
        }
    }
    EXPECT_EQ(activeCount, PROXY_POLICY_MAX_SIZE);
}

/**
 * @tc.name: ProxyGetRetryConfigAclConnectedExceedStage1
 * @tc.desc: test ACL connected with innerRetryNum beyond stage 1 is not retryable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, ProxyGetRetryConfigAclConnectedExceedStage1, TestSize.Level1)
{
    ProxyConnectInfo info = { .isAclConnected = true, .innerRetryNum = 7 };
    auto config = ProxyGetRetryConfig(GetProxyConfigManager(), &info);
    EXPECT_FALSE(config.retryable);
    EXPECT_EQ(config.delayMs, 0);
}

/**
 * @tc.name: ProxyGetRetryConfigAclDisconnectedBoundary
 * @tc.desc: test ACL disconnected stage boundary at innerRetryNum=4
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, ProxyGetRetryConfigAclDisconnectedBoundary, TestSize.Level1)
{
    // innerRetryNum=3 is still in stage 2 (15s)
    ProxyConnectInfo info = { .isAclConnected = false, .innerRetryNum = 3 };
    auto config = ProxyGetRetryConfig(GetProxyConfigManager(), &info);
    EXPECT_TRUE(config.retryable);
    EXPECT_EQ(config.delayMs, 15000);

    // innerRetryNum=4 transitions to stage 3 (120s)
    info.innerRetryNum = 4;
    config = ProxyGetRetryConfig(GetProxyConfigManager(), &info);
    EXPECT_TRUE(config.retryable);
    EXPECT_EQ(config.delayMs, 120000);
}

/**
 * @tc.name: ProxyGetRetryConfigAclConnectedFirstRetry
 * @tc.desc: test ACL connected first retry returns delayMs=0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, ProxyGetRetryConfigAclConnectedFirstRetry, TestSize.Level1)
{
    ProxyConnectInfo info = { .isAclConnected = true, .innerRetryNum = 0 };
    auto config = ProxyGetRetryConfig(GetProxyConfigManager(), &info);
    EXPECT_TRUE(config.retryable);
    EXPECT_EQ(config.delayMs, 0);
}

/**
 * @tc.name: ProxyGetRetryConfigAclDisconnectedExceedAllStages
 * @tc.desc: test ACL disconnected with innerRetryNum beyond all stages is not retryable
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, ProxyGetRetryConfigAclDisconnectedExceedAllStages, TestSize.Level1)
{
    ProxyConnectInfo info = { .isAclConnected = false, .innerRetryNum = 9 };
    auto config = ProxyGetRetryConfig(GetProxyConfigManager(), &info);
    EXPECT_FALSE(config.retryable);
    EXPECT_EQ(config.delayMs, 0);
}

/**
 * @tc.name: ProxyGetRetryConfigNearMaxRetryTimes
 * @tc.desc: test innerRetryNum = PROXY_RETRY_MAX_TIMES - 1 passes limit check but no policy matches
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, ProxyGetRetryConfigNearMaxRetryTimes, TestSize.Level1)
{
    ProxyConnectInfo info = { .isAclConnected = false, .innerRetryNum = PROXY_RETRY_MAX_TIMES - 1 };
    auto config = ProxyGetRetryConfig(GetProxyConfigManager(), &info);
    EXPECT_FALSE(config.retryable);
    EXPECT_EQ(config.delayMs, 0);
}

/**
 * @tc.name: ProxyGetRetryConfigAllPoliciesInactive
 * @tc.desc: test ProxyGetRetryConfig with a manager whose policies are all inactive
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, ProxyGetRetryConfigAllPoliciesInactive, TestSize.Level1)
{
    ProxyConfigManager mgr = {};
    ProxyConnectInfo info = { .isAclConnected = true, .innerRetryNum = 0 };
    auto config = ProxyGetRetryConfig(&mgr, &info);
    EXPECT_FALSE(config.retryable);
    EXPECT_EQ(config.delayMs, 0);
}

/**
 * @tc.name: ProxyConfigPolicyIsActiveWithMatchNullExecuteSet
 * @tc.desc: test active=true, Match=null, Execute=set is not active
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ProxyConfigTest, ProxyConfigPolicyIsActiveWithMatchNullExecuteSet, TestSize.Level1)
{
    ProxyConfigPolicy configPolicy = {};
    configPolicy.active = true;
    configPolicy.Execute = [](const ProxyConfigPolicy *policy, const ProxyConnectInfo *info) {
        (void)policy;
        (void)info;
        return static_cast<uint64_t>(0);
    };
    auto active = ProxyConfigPolicyIsActive(&configPolicy);
    EXPECT_FALSE(active);
}
