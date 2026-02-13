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

#ifndef PROXY_CHANNEL_CONFIG_H
#define PROXY_CHANNEL_CONFIG_H

#include <stdint.h>

#include "proxy_manager.h"

#define PROXY_POLICY_MAX_SIZE 3
#define PROXY_RETRY_MAX_TIMES 64

#ifdef __cplusplus
extern "C" {
#endif

struct ProxyConfigPolicy {
    bool active;

    // range is [stat, end)
    uint32_t start;
    uint32_t end;
    uint32_t delayMs;
    uint32_t value;

    bool (*Match)(const struct ProxyConfigPolicy *policy, const ProxyConnectInfo *info);
    uint64_t (*Execute)(const struct ProxyConfigPolicy *policy, const ProxyConnectInfo *info);
};
bool ProxyConfigPolicyIsActive(const struct ProxyConfigPolicy *policy);

struct ProxyConfigManager {
    struct ProxyConfigPolicy policies[PROXY_POLICY_MAX_SIZE];
};
struct ProxyConfigManager *GetProxyConfigManager(void);

struct ProxyConfig {
    bool retryable;
    uint64_t delayMs;
};
struct ProxyConfig ProxyGetRetryConfig(struct ProxyConfigManager *mgr, const ProxyConnectInfo *info);

#ifdef __cplusplus
}
#endif

#endif