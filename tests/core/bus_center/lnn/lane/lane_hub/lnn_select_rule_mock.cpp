/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "lnn_select_rule_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_lnnSelectRuleInterface;
LnnSelectRuleInterfaceMock::LnnSelectRuleInterfaceMock()
{
    g_lnnSelectRuleInterface = static_cast<void *>(this);
}

LnnSelectRuleInterfaceMock::~LnnSelectRuleInterfaceMock()
{
    g_lnnSelectRuleInterface = nullptr;
}

static LnnSelectRuleInterface *GetLnnSelectRuleInterface()
{
    return static_cast<LnnSelectRuleInterface *>(g_lnnSelectRuleInterface);
}

extern "C" {
int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetLnnSelectRuleInterface()->LnnGetLocalNumU32Info(key, info);
}

int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info)
{
    return GetLnnSelectRuleInterface()->LnnGetRemoteNumU32Info(networkId, key, info);
}

int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len)
{
    return GetLnnSelectRuleInterface()->LnnGetRemoteStrInfo(netWorkId, key, info, len);
}
}
} // namespace OHOS
