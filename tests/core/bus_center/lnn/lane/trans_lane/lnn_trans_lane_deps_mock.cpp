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
#include "softbus_error_code.h"

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

int32_t TransLaneDepsInterfaceMock::ActionOfLaneLinkSuccess(const LinkRequest *reqInfo,
    uint32_t reqId, const LaneLinkCb *cb)
{
    LaneLinkInfo linkInfo = {
        .type = reqInfo->linkType,
    };
    cb->onLaneLinkSuccess(reqId, reqInfo->linkType, &linkInfo);
    return SOFTBUS_OK;
}

int32_t TransLaneDepsInterfaceMock::ActionOfLaneLinkFail(const LinkRequest *reqInfo,
    uint32_t reqId, const LaneLinkCb *cb)
{
    cb->onLaneLinkFail(reqId, SOFTBUS_LANE_TRIGGER_LINK_FAIL, reqInfo->linkType);
    return SOFTBUS_OK;
}

extern "C" {
int32_t SelectAuthLane(const char *networkId, LanePreferredLinkList *recommendList, LanePreferredLinkList *request)
{
    return GetTransLaneIf()->SelectAuthLane(networkId, recommendList, request);
}

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

int32_t DestroyLink(const char *networkId, uint32_t laneReqId, LaneLinkType type)
{
    return GetTransLaneIf()->DestroyLink(networkId, laneReqId, type);
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

int32_t DelLaneResourceByLaneId(uint64_t laneId, bool isServerSide)
{
    return GetTransLaneIf()->DelLaneResourceByLaneId(laneId, isServerSide);
}

int32_t FindLaneResourceByLaneId(uint64_t laneId, LaneResource *resourceItem)
{
    return GetTransLaneIf()->FindLaneResourceByLaneId(laneId, resourceItem);
}

void FreeLaneReqId(uint32_t laneReqId)
{
    GetTransLaneIf()->FreeLaneReqId(laneReqId);
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

uint64_t GenerateLaneId(const char *localUdid, const char *remoteUdid, LaneLinkType linkType)
{
    return GetTransLaneIf()->GenerateLaneId(localUdid, remoteUdid, linkType);
}

int32_t LaneCheckLinkValid(const char *networkId, LaneLinkType linkType, LaneTransType transType)
{
    return GetTransLaneIf()->LaneCheckLinkValid(networkId, linkType, transType);
}

int32_t GetErrCodeOfLink(const char *networkId, LaneLinkType linkType)
{
    return GetTransLaneIf()->GetErrCodeOfLink(networkId, linkType);
}

int32_t CheckLaneResourceNumByLinkType(const char *peerUdid, LaneLinkType type, int32_t *laneNum)
{
    return GetTransLaneIf()->CheckLaneResourceNumByLinkType(peerUdid, type, laneNum);
}

void DetectEnableWifiDirectApply(void)
{
    GetTransLaneIf()->DetectEnableWifiDirectApply();
}

void DetectDisableWifiDirectApply(void)
{
    GetTransLaneIf()->DetectDisableWifiDirectApply();
}

int32_t CheckLinkConflictByReleaseLink(LaneLinkType releaseLink)
{
    return GetTransLaneIf()->CheckLinkConflictByReleaseLink(releaseLink);
}
}
} // namespace OHOS