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

#include "lnn_lane_select_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_laneSelectInterface;
LaneSelectInterfaceMock::LaneSelectInterfaceMock()
{
    g_laneSelectInterface = reinterpret_cast<void *>(this);
}

LaneSelectInterfaceMock::~LaneSelectInterfaceMock()
{
    g_laneSelectInterface = nullptr;
}

static LaneSelectInterface *GetLaneSelectInterface()
{
    return reinterpret_cast<LaneSelectInterface *>(g_laneSelectInterface);
}

extern "C" {
uint64_t SoftBusGetSysTimeMs(void)
{
    return GetLaneSelectInterface()->SoftBusGetSysTimeMs();
}
}
} // namespace OHOS