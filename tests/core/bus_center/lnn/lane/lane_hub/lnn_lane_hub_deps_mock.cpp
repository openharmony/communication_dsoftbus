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

#include "lnn_lane_hub_deps_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_laneHubDepsInterface;
LaneHubDepsInterfaceMock::LaneHubDepsInterfaceMock()
{
    g_laneHubDepsInterface = reinterpret_cast<void *>(this);
}

LaneHubDepsInterfaceMock::~LaneHubDepsInterfaceMock()
{
    g_laneHubDepsInterface = nullptr;
}

static LaneHubDepsInterface *GetLaneHubDepsInterface()
{
    return reinterpret_cast<LaneHubDepsInterface *>(g_laneHubDepsInterface);
}

extern "C" {
int32_t InitLane(void)
{
    return GetLaneHubDepsInterface()->InitLane();
}

int32_t LnnInitQos(void)
{
    return GetLaneHubDepsInterface()->LnnInitQos();
}

int32_t LnnInitTimeSync(void)
{
    return GetLaneHubDepsInterface()->LnnInitTimeSync();
}

int32_t LnnInitHeartbeat(void)
{
    return GetLaneHubDepsInterface()->LnnInitHeartbeat();
}

int32_t LnnStartHeartbeatFrameDelay(void)
{
    return GetLaneHubDepsInterface()->LnnStartHeartbeatFrameDelay();
}

void LnnDeinitQos(void)
{
    return GetLaneHubDepsInterface()->LnnDeinitQos();
}

void DeinitLane(void)
{
    return GetLaneHubDepsInterface()->DeinitLane();
}

void LnnDeinitTimeSync(void)
{
    return GetLaneHubDepsInterface()->LnnDeinitTimeSync();
}

void LnnDeinitHeartbeat(void)
{
    return GetLaneHubDepsInterface()->LnnDeinitHeartbeat();
}
}
} // namespace OHOS
