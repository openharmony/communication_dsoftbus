/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "lnn_trans_lane_deps_mock.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_transLaneIf;
TransLaneDepsInterfaceMock::TransLaneDepsInterfaceMock()
{
    g_transLaneIf = reinterpret_cast<void *>(this);
}

TransLaneDepsInterfaceMock::~TransLaneDepsInterfaceMock()
{
    g_transLaneIf = nullptr;
}

static TransLaneDepsInterface *GetTransLaneIf()
{
    return reinterpret_cast<TransLaneDepsInterface *>(g_transLaneIf);
}

extern "C" {
int32_t SelectLane(const char *networkId, const LaneSelectParam *request,
    LaneLinkType **linkList, uint32_t *listNum)
{
    return GetTransLaneIf()->SelectLane(networkId, request, linkList, listNum);
}

int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *cb)
{
    return GetTransLaneIf()->BuildLink(reqInfo, reqId, cb);
}

void DestroyLink(uint32_t reqId, LaneLinkType type, int32_t pid,
    const char *mac, const char *networkId)
{
    GetTransLaneIf()->DestroyLink(reqId, type, pid, mac, networkId);
}

uint32_t GenerateLaneProfileId(const LaneGenerateParam *param)
{
    return GetTransLaneIf()->GenerateLaneProfileId(param);
}

void UnbindLaneIdFromProfile(uint32_t laneId, uint32_t profileId)
{
    GetTransLaneIf()->UnbindLaneIdFromProfile(laneId, profileId);
}

int32_t BindLaneIdToProfile(uint32_t laneId, LaneProfile *profile)
{
    return GetTransLaneIf()->BindLaneIdToProfile(laneId, profile);
}
}
} // namespace OHOS