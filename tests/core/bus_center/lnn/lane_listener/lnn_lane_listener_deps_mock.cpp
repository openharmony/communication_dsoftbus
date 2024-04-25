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
uint64_t ApplyLaneId(const char *localUdid, const char *remoteUdid, LaneLinkType linkType)
{
    return GetLaneListenerDepsInterface()->ApplyLaneId(localUdid, remoteUdid, linkType);
}
}
} // namespace OHOS
