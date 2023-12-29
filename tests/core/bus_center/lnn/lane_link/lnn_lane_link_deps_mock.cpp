/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "lnn_lane_link_deps_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_laneLinkDepsInterface;
LaneLinkDepsInterfaceMock::LaneLinkDepsInterfaceMock()
{
    g_laneLinkDepsInterface = reinterpret_cast<void *>(this);
}

LaneLinkDepsInterfaceMock::~LaneLinkDepsInterfaceMock()
{
    g_laneLinkDepsInterface = nullptr;
}

static LaneLinkDepsInterface *GetLaneLinkDepsInterface()
{
    return reinterpret_cast<LaneLinkDepsInterface *>(g_laneLinkDepsInterface);
}

extern "C" {
int32_t GetTransOptionByLaneId(uint32_t laneId, TransOption *reqInfo)
{
    return GetLaneLinkDepsInterface()->GetTransOptionByLaneId(laneId, reqInfo);
}
}
} // namespace OHOS
