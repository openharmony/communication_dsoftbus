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

#include "lnn_lane_link_p2p_deps_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_laneLinkP2pDepsInterface;
LaneLinkP2pDepsInterfaceMock::LaneLinkP2pDepsInterfaceMock()
{
    g_laneLinkP2pDepsInterface = reinterpret_cast<void *>(this);
}

LaneLinkP2pDepsInterfaceMock::~LaneLinkP2pDepsInterfaceMock()
{
    g_laneLinkP2pDepsInterface = nullptr;
}

static LaneLinkP2pDepsInterface *GetLaneLinkP2pDepsInterface()
{
    return reinterpret_cast<LaneLinkP2pDepsInterface *>(g_laneLinkP2pDepsInterface);
}

extern "C" {
LnnEnhanceFuncList *LnnEnhanceFuncListGet(void)
{
    return GetLaneLinkP2pDepsInterface()->LnnEnhanceFuncListGet();
}

bool IsEnhancedWifiDirectSupported(const char *networkId)
{
    return GetLaneLinkP2pDepsInterface()->IsEnhancedWifiDirectSupported(networkId);
}
}
} // namespace OHOS
