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

#include "lnn_lane_listener_deps_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_laneListanerDepsInterface;
LaneListenerDepsInterfaceMock::LaneListenerDepsInterfaceMock()
{
    g_laneListanerDepsInterface = reinterpret_cast<void *>(this);
}

LaneListenerDepsInterfaceMock::~LaneListenerDepsInterfaceMock()
{
    g_laneListanerDepsInterface = nullptr;
}

static LaneListenerDepsInterface *GetLaneListenerDepsInterface()
{
    return reinterpret_cast<LaneListenerDepsInterface *>(g_laneListanerDepsInterface);
}

extern "C" {
int32_t FreeLaneResource(const LaneResource *resourceItem)
{
    return GetLaneListenerDepsInterface()->FreeLaneResource(resourceItem);
}

int32_t LaneInfoProcess(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    return GetLaneListenerDepsInterface()->LaneInfoProcess(linkInfo, connInfo, profile);
}

int32_t PostLaneStateChangeMessage(LaneState state, const char *peerUdid, const LaneLinkInfo *laneLinkInfo)
{
    return GetLaneListenerDepsInterface()->PostLaneStateChangeMessage(state, peerUdid, laneLinkInfo);
}

int32_t FindLaneResourceByLinkAddr(const LaneLinkInfo *infoItem, LaneResource *resourceItem)
{
    return GetLaneListenerDepsInterface()->FindLaneResourceByLinkAddr(infoItem, resourceItem);
}

uint64_t GenerateLaneId(const char *localUdid, const char *remoteUdid, LaneLinkType linkType)
{
    return GetLaneListenerDepsInterface()->GenerateLaneId(localUdid, remoteUdid, linkType);
}

int32_t FindLaneResourceByLinkType(const char *peerUdid, LaneLinkType type, LaneResource *resource)
{
    return GetLaneListenerDepsInterface()->FindLaneResourceByLinkType(peerUdid, type, resource);
}

void DelLogicAndLaneRelationship(uint64_t laneId)
{
    GetLaneListenerDepsInterface()->DelLogicAndLaneRelationship(laneId);
}

int32_t ClearLaneResourceByLaneId(uint64_t laneId)
{
    return GetLaneListenerDepsInterface()->ClearLaneResourceByLaneId(laneId);
}

void RemoveDelayDestroyMessage(uint64_t laneId)
{
    GetLaneListenerDepsInterface()->RemoveDelayDestroyMessage(laneId);
}

int32_t AddLaneResourceToPool(const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide)
{
    return GetLaneListenerDepsInterface()->AddLaneResourceToPool(linkInfo, laneId, isServerSide);
}

int32_t DelLaneResourceByLaneId(uint64_t laneId, bool isServerSide)
{
    return GetLaneListenerDepsInterface()->DelLaneResourceByLaneId(laneId, isServerSide);
}

void DetectDisableWifiDirectApply(void)
{
    GetLaneListenerDepsInterface()->DetectDisableWifiDirectApply();
}

int32_t HandleLaneQosChange(const LaneLinkInfo *laneLinkInfo)
{
    return GetLaneListenerDepsInterface()->HandleLaneQosChange(laneLinkInfo);
}
}
} // namespace OHOS
