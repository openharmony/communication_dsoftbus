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

void DestroyLink(const char *networkId, uint32_t laneReqId, LaneLinkType type)
{
    GetTransLaneIf()->DestroyLink(networkId, laneReqId, type);
}

uint32_t GenerateLaneProfileId(const LaneGenerateParam *param)
{
    return GetTransLaneIf()->GenerateLaneProfileId(param);
}

void UnbindLaneReqIdFromProfile(uint32_t laneReqId, uint32_t profileId)
{
    GetTransLaneIf()->UnbindLaneReqIdFromProfile(laneReqId, profileId);
}

int32_t BindLaneIdToProfile(uint64_t laneId, LaneProfile *profile)
{
    return GetTransLaneIf()->BindLaneIdToProfile(laneId, profile);
}

int32_t AddLaneResourceToPool(const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide)
{
    return GetTransLaneIf()->AddLaneResourceToPool(linkInfo, laneId, isServerSide);
}

int32_t DelLaneResourceByLaneId(uint64_t laneId)
{
    return GetTransLaneIf()->DelLaneResourceByLaneId(laneId);
}

int32_t FindLaneResourceByLaneId(uint64_t laneId, LaneResource *resourceItem)
{
    return GetTransLaneIf()->FindLaneResourceByLaneId(laneId, resourceItem);
}

void FreeLaneReqId(uint32_t laneReqId)
{
    return GetTransLaneIf()->FreeLaneReqId(laneReqId);
}

int32_t SelectExpectLaneByParameter(LanePreferredLinkList *setRecommendLinkList)
{
    return GetTransLaneIf()->SelectExpectLaneByParameter(setRecommendLinkList);
}

int32_t AddLaneBusinessInfoItem(LaneType laneType, uint64_t laneId)
{
    return GetTransLaneIf()->AddLaneBusinessInfoItem(laneType, laneId);
}

int32_t DelLaneBusinessInfoItem(LaneType laneType, uint64_t laneId)
{
    return GetTransLaneIf()->DelLaneBusinessInfoItem(laneType, laneId);
}

int32_t LaneLinkupNotify(const char *peerUdid, const LaneLinkInfo *laneLinkInfo)
{
    return GetTransLaneIf()->LaneLinkupNotify(peerUdid, laneLinkInfo);
}

int32_t LaneLinkdownNotify(const char *peerUdid, const LaneLinkInfo *laneLinkInfo)
{
    return GetTransLaneIf()->LaneLinkdownNotify(peerUdid, laneLinkInfo);
}

uint64_t ApplyLaneId(const char *activeUdid, const char *passiveUdid, LaneLinkType linkType)
{
    return GetTransLaneIf()->ApplyLaneId(activeUdid, passiveUdid, linkType);
}
}
} // namespace OHOS