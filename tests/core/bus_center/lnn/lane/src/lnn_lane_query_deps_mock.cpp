/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "lnn_lane_query_deps_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_laneQueryDepsInterface;
LaneQueryDepsInterfaceMock::LaneQueryDepsInterfaceMock()
{
    g_laneQueryDepsInterface = reinterpret_cast<void *>(this);
}

LaneQueryDepsInterfaceMock::~LaneQueryDepsInterfaceMock()
{
    g_laneQueryDepsInterface = nullptr;
}

static LaneQueryDepsInterface *GetLaneQueryDepsInterface()
{
    return reinterpret_cast<LaneQueryDepsInterface *>(g_laneQueryDepsInterface);
}

extern "C" {
int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetLaneQueryDepsInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetLaneQueryDepsInterface()->LnnHasDiscoveryType(info, type);
}

struct WifiDirectManager* GetWifiDirectManager(void)
{
    return GetLaneQueryDepsInterface()->GetWifiDirectManager();
}

int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info)
{
    return GetLaneQueryDepsInterface()->LnnGetRemoteNumU32Info(networkId, key, info);
}

int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetLaneQueryDepsInterface()->LnnGetLocalNumU32Info(key, info);
}

SoftBusWifiDetailState SoftBusGetWifiState(void)
{
    return GetLaneQueryDepsInterface()->SoftBusGetWifiState();
}

bool SoftBusIsWifiActive(void)
{
    return GetLaneQueryDepsInterface()->SoftBusIsWifiActive();
}

bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    return GetLaneQueryDepsInterface()->IsFeatureSupport(feature, capaBit);
}

int32_t LnnGetRemoteBoolInfo(const char *networkId, InfoKey key, bool *info)
{
    return GetLaneQueryDepsInterface()->LnnGetRemoteBoolInfo(networkId, key, info);
}

uint64_t LnnGetFeatureCapabilty(void)
{
    return GetLaneQueryDepsInterface()->LnnGetFeatureCapabilty();
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    return GetLaneQueryDepsInterface()->LnnGetOnlineStateById(id, type);
}
}
} // namespace OHOS