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

#include "proxy_config.h"

#include <math.h>
#include <stdlib.h>

#include "conn_log.h"

#define POLICY_STAGE_1_START 0
#define POLICY_STAGE_1_END   (POLICY_STAGE_1_START + 7)
#define POLICY_STAGE_2_START 0
#define POLICY_STAGE_2_END   (POLICY_STAGE_2_START + 4)
#define POLICY_STAGE_3_START (POLICY_STAGE_2_END)
#define POLICY_STAGE_3_END   (POLICY_STAGE_3_START + 5)

#define POLICY_BACKOFF_FACTOR_MS      (1 * 1000)
#define POLICY_STAGE_1_FIRST_DELAY_MS (0 * 1000)
#define POLICY_STAGE_2_FIXED_DELAY_MS (15 * 1000)
#define POLICY_STAGE_3_FIXED_DELAY_MS (120 * 1000)

#define POLICY_BACKOFF_BASE 2

bool ProxyConfigPolicyIsActive(const struct ProxyConfigPolicy *policy)
{
    CONN_CHECK_AND_RETURN_RET_LOGE(policy != NULL, false, CONN_PROXY, "policy is null");
    return policy->active && policy->Match != NULL && policy->Execute != NULL;
}

static bool RangeMatcher(const struct ProxyConfigPolicy *policy, const ProxyConnectInfo *info)
{
    // range is [stat, end)
    return info->innerRetryNum >= policy->start && info->innerRetryNum < policy->end;
}

static bool ProxyDisconnectedStateMatcher(const struct ProxyConfigPolicy *policy, const ProxyConnectInfo *info)
{
    return !info->isAclConnected && RangeMatcher(policy, info);
}

static bool ProxyConnectedStateMatcher(const struct ProxyConfigPolicy *policy, const ProxyConnectInfo *info)
{
    return info->isAclConnected && RangeMatcher(policy, info);
}

static uint64_t FixPolicyExecutor(const struct ProxyConfigPolicy *policy, const ProxyConnectInfo *info)
{
    (void)info;
    return policy->delayMs;
}

static uint64_t BackoffPolicyExecutor(const struct ProxyConfigPolicy *policy, const ProxyConnectInfo *info)
{
    if (info->innerRetryNum == 0) {
        return policy->delayMs;
    }
    return pow(POLICY_BACKOFF_BASE, info->innerRetryNum - 1) * policy->value + policy->delayMs;
}

struct ProxyConfigManager *GetProxyConfigManager(void)
{
    static bool init = false;
    static struct ProxyConfigManager config = { 0 };

    if (init) {
        return &config;
    }

    uint8_t index = 0;
    config.policies[index].active = true;
    config.policies[index].start = POLICY_STAGE_1_START;
    config.policies[index].end = POLICY_STAGE_1_END;
    config.policies[index].delayMs = POLICY_STAGE_1_FIRST_DELAY_MS;
    config.policies[index].value = POLICY_BACKOFF_FACTOR_MS;
    config.policies[index].Match = ProxyConnectedStateMatcher;
    config.policies[index].Execute = BackoffPolicyExecutor;

    index++;
    config.policies[index].active = true;
    config.policies[index].start = POLICY_STAGE_2_START;
    config.policies[index].end = POLICY_STAGE_2_END;
    config.policies[index].delayMs = POLICY_STAGE_2_FIXED_DELAY_MS;
    config.policies[index].value = 0;
    config.policies[index].Match = ProxyDisconnectedStateMatcher;
    config.policies[index].Execute = FixPolicyExecutor;

    index++;
    config.policies[index].active = true;
    config.policies[index].start = POLICY_STAGE_3_START;
    config.policies[index].end = POLICY_STAGE_3_END;
    config.policies[index].delayMs = POLICY_STAGE_3_FIXED_DELAY_MS;
    config.policies[index].value = 0;
    config.policies[index].Match = ProxyDisconnectedStateMatcher;
    config.policies[index].Execute = FixPolicyExecutor;

    init = true;
    return &config;
}

struct ProxyConfig ProxyGetRetryConfig(struct ProxyConfigManager *mgr, const ProxyConnectInfo *info)
{
    struct ProxyConfig mismatch = { .retryable = false, .delayMs = 0 };
    CONN_CHECK_AND_RETURN_RET_LOGE(mgr != NULL, mismatch, CONN_PROXY, "proxy config manager is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(info != NULL, mismatch, CONN_PROXY, "proxy connect info is null");
    CONN_CHECK_AND_RETURN_RET_LOGE(info->innerRetryNum < PROXY_RETRY_MAX_TIMES, mismatch, CONN_PROXY,
        "retry times=%{public}u exceed policy limit", info->innerRetryNum);

    for (size_t i = 0; i < ARRAY_SIZE(mgr->policies); i++) {
        struct ProxyConfigPolicy *policy = &mgr->policies[i];
        if (ProxyConfigPolicyIsActive(policy) && policy->Match(policy, info)) {
            uint64_t result = policy->Execute(policy, info);
            struct ProxyConfig config = { .retryable = true, .delayMs = result };
            return config;
        }
    }
    CONN_LOGW(CONN_PROXY, "policy mismatch, acl state=%{public}d, retry times=%{public}u", info->isAclConnected,
        info->innerRetryNum);
    return mismatch;
}
