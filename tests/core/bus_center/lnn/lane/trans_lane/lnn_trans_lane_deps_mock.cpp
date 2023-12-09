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
    LanePreferredLinkList *recommendList, uint32_t *listNum)
{
    return GetTransLaneIf()->SelectLane(networkId, request, recommendList, listNum);
}

int32_t SelectExpectLanesByQos(const char *networkId, const LaneSelectParam *request,
    LanePreferredLinkList *recommendList)
{
        return GetTransLaneIf()->SelectExpectLanesByQos(networkId, request, recommendList);
}

int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *cb)
{
    return GetTransLaneIf()->BuildLink(reqInfo, reqId, cb);
}

void DestroyLink(const char *networkId, uint32_t reqId, LaneLinkType type, int32_t pid)
{
    GetTransLaneIf()->DestroyLink(networkId, reqId, type, pid);
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
int32_t AddLaneResourceItem(const LaneResource *resourceItem)
{
    return GetTransLaneIf()->AddLaneResourceItem(resourceItem);
}
int32_t DelLaneResourceItem(const LaneResource *resourceItem)
{
    return GetTransLaneIf()->DelLaneResourceItem(resourceItem);
}
int32_t AddLinkInfoItem(const LaneLinkInfo *linkInfoItem)
{
    return GetTransLaneIf()->AddLinkInfoItem(linkInfoItem);
}
int32_t DelLinkInfoItem(uint32_t laneId)
{
    return GetTransLaneIf()->DelLinkInfoItem(laneId);
}
int32_t FindLaneLinkInfoByLaneId(uint32_t laneId, LaneLinkInfo *linkInfoitem)
{
    return GetTransLaneIf()->FindLaneLinkInfoByLaneId(laneId, linkInfoitem);
}
int32_t ConvertToLaneResource(const LaneLinkInfo *linkInfo, LaneResource *laneResourceInfo)
{
    return GetTransLaneIf()->ConvertToLaneResource(linkInfo, laneResourceInfo);
}

int32_t DelLaneResourceItemWithDelay(LaneResource *resourceItem, uint32_t laneId, bool *isDelayDestroy)
{
    return GetTransLaneIf()->DelLaneResourceItemWithDelay(resourceItem, laneId, isDelayDestroy);
}

void FreeLaneId(uint32_t laneId)
{
    return GetTransLaneIf()->FreeLaneId(laneId);
}

void HandleLaneReliabilityTime(void)
{
    return GetTransLaneIf()->HandleLaneReliabilityTime();
}
}
} // namespace OHOS