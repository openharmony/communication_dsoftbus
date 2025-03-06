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

#include "lnn_lane_net_capability_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_laneNetCapIf;
LaneNetCapInterfaceMock::LaneNetCapInterfaceMock()
{
    g_laneNetCapIf = static_cast<void *>(this);
}

LaneNetCapInterfaceMock::~LaneNetCapInterfaceMock()
{
    g_laneNetCapIf = nullptr;
}

static LaneNetCapInterface *GetLaneNetCapIf()
{
    return static_cast<LaneNetCapInterface *>(g_laneNetCapIf);
}

static int32_t GetStaticCommCapa(const char *networkId)
{
    return SOFTBUS_OK;
}

static int32_t GetDynamicCommCapa(const char *networkId)
{
    return SOFTBUS_OK;
}

LaneCommCapa g_laneCommCapa = {
    .getStaticCommCapa = GetStaticCommCapa,
    .getDynamicCommCapa = GetDynamicCommCapa,
};

LaneCommCapa *LaneNetCapInterfaceMock::ActionGetLinkCapaByLinkType(LaneLinkType linkType)
{
    return &g_laneCommCapa;
}

extern "C" {
void SetRemoteDynamicNetCap(const char *peerUdid, NetCapability netCapaIndex)
{
    GetLaneNetCapIf()->SetRemoteDynamicNetCap(peerUdid, netCapaIndex);
}

LaneCommCapa *GetLinkCapaByLinkType(LaneLinkType linkType)
{
    return GetLaneNetCapIf()->GetLinkCapaByLinkType(linkType);
}
}
} // namespace OHOS
