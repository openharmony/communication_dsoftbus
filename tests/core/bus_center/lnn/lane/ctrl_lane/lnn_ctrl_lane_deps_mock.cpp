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

#include "lnn_ctrl_lane_deps_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_ctrlLaneIf;
CtrlLaneDepsInterfaceMock::CtrlLaneDepsInterfaceMock()
{
    g_ctrlLaneIf = static_cast<void *>(this);
}

CtrlLaneDepsInterfaceMock::~CtrlLaneDepsInterfaceMock()
{
    g_ctrlLaneIf = nullptr;
}

static CtrlLaneDepsInterface *GetCtrlLaneIf()
{
    return static_cast<CtrlLaneDepsInterfaceMock *>(g_ctrlLaneIf);
}

int32_t CtrlLaneDepsInterfaceMock::BuildLinkSuccess(const LinkRequest *reqInfo, uint32_t reqId,
    const LaneLinkCb *callback)
{
    LaneLinkInfo linkInfo = {};
    linkInfo.type = reqInfo->linkType;
    callback->onLaneLinkSuccess(reqId, reqInfo->linkType, &linkInfo);
    return SOFTBUS_OK;
}

int32_t CtrlLaneDepsInterfaceMock::BuildLinkFail(const LinkRequest *reqInfo, uint32_t reqId,
    const LaneLinkCb *callback)
{
    callback->onLaneLinkFail(reqId, SOFTBUS_LANE_TRIGGER_LINK_FAIL, reqInfo->linkType);
    return SOFTBUS_OK;
}

extern "C" {
int32_t SelectAuthLane(const char *networkId, LanePreferredLinkList *recommendList, LanePreferredLinkList *request)
{
    return GetCtrlLaneIf()->SelectAuthLane(networkId, recommendList, request);
}

int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *callback)
{
    return GetCtrlLaneIf()->BuildLink(reqInfo, reqId, callback);
}

int32_t DestroyLink(const char *networkId, uint32_t laneReqId, LaneLinkType type)
{
    return GetCtrlLaneIf()->DestroyLink(networkId, laneReqId, type);
}

uint64_t GenerateLaneId(const char *localUdid, const char *remoteUdid, LaneLinkType linkType)
{
    return GetCtrlLaneIf()->GenerateLaneId(localUdid, remoteUdid, linkType);
}

int32_t AddLaneResourceToPool(const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide)
{
    return GetCtrlLaneIf()->AddLaneResourceToPool(linkInfo, laneId, isServerSide);
}

int32_t DelLaneResourceByLaneId(uint64_t laneId, bool isServerSide)
{
    return GetCtrlLaneIf()->DelLaneResourceByLaneId(laneId, isServerSide);
}

int32_t FindLaneResourceByLaneId(uint64_t laneId, LaneResource *resourceItem)
{
    return GetCtrlLaneIf()->FindLaneResourceByLaneId(laneId, resourceItem);
}

int32_t FindLaneResourceByLinkType(const char *peerUdid, LaneLinkType type, LaneResource *resource)
{
    return GetCtrlLaneIf()->FindLaneResourceByLinkType(peerUdid, type, resource);
}

void FreeLaneReqId(uint32_t laneReqId)
{
    GetCtrlLaneIf()->FreeLaneReqId(laneReqId);
}

int32_t LaneInfoProcess(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile)
{
    return GetCtrlLaneIf()->LaneInfoProcess(linkInfo, connInfo, profile);
}
}
} // namespace OHOS
