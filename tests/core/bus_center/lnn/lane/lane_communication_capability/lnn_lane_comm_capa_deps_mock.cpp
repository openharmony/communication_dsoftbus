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

#include "lnn_lane_comm_capa_deps_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_laneCommCapaIf;
LaneCommCapaDepsInterfaceMock::LaneCommCapaDepsInterfaceMock()
{
    g_laneCommCapaIf = static_cast<void *>(this);
}

LaneCommCapaDepsInterfaceMock::~LaneCommCapaDepsInterfaceMock()
{
    g_laneCommCapaIf = nullptr;
}

static LaneCommCapaDepsInterface *GetLaneCommCapaIf()
{
    return static_cast<LaneCommCapaDepsInterface *>(g_laneCommCapaIf);
}

extern "C" {
int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info)
{
    return GetLaneCommCapaIf()->LnnGetLocalNumU32Info(key, info);
}

int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info)
{
    return GetLaneCommCapaIf()->LnnGetRemoteNumU32Info(networkId, key, info);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetLaneCommCapaIf()->LnnGetRemoteNodeInfoById(id, type, info);
}

bool LnnHasDiscoveryType(const NodeInfo *info, DiscoveryType type)
{
    return GetLaneCommCapaIf()->LnnHasDiscoveryType(info, type);
}

SoftBusWifiDetailState SoftBusGetWifiState(void)
{
    return GetLaneCommCapaIf()->SoftBusGetWifiState();
}

int32_t LnnGetNetworkIdByUdid(const char *udid, char *buf, uint32_t len)
{
    return GetLaneCommCapaIf()->LnnGetNetworkIdByUdid(udid, buf, len);
}
}
} // namespace OHOS
