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

#ifndef LNN_CTRL_LANE_DEPS_MOCK_H
#define LNN_CTRL_LANE_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "lnn_lane_link.h"

namespace OHOS {
class CtrlLaneDepsInterface {
public:
    CtrlLaneDepsInterface() {};
    virtual ~CtrlLaneDepsInterface() {};

    virtual int32_t SelectAuthLane(const char *networkId, LanePreferredLinkList *recommendList,
        LanePreferredLinkList *request) = 0;
    virtual int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *callback) = 0;
    virtual int32_t DestroyLink(const char *networkId, uint32_t laneReqId, LaneLinkType type) = 0;
    virtual uint64_t GenerateLaneId(const char *localUdid, const char *remoteUdid, LaneLinkType linkType) = 0;
    virtual int32_t AddLaneResourceToPool(const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide) = 0;
    virtual int32_t DelLaneResourceByLaneId(uint64_t laneId, bool isServerSide) = 0;
    virtual int32_t FindLaneResourceByLaneId(uint64_t laneId, LaneResource *resourceItem) = 0;
    virtual int32_t FindLaneResourceByLinkType(const char *peerUdid, LaneLinkType type, LaneResource *resource) = 0;
    virtual void FreeLaneReqId(uint32_t laneReqId) = 0;
    virtual int32_t LaneInfoProcess(const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo, LaneProfile *profile) = 0;
};

class CtrlLaneDepsInterfaceMock : public CtrlLaneDepsInterface {
public:
    CtrlLaneDepsInterfaceMock();
    ~CtrlLaneDepsInterfaceMock() override;

    MOCK_METHOD3(SelectAuthLane, int32_t (const char *, LanePreferredLinkList *, LanePreferredLinkList *));
    MOCK_METHOD3(BuildLink, int32_t (const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *callback));
    MOCK_METHOD3(DestroyLink, int32_t (const char *networkId, uint32_t laneReqId, LaneLinkType type));
    MOCK_METHOD3(GenerateLaneId, uint64_t (const char *localUdid, const char *remoteUdid, LaneLinkType linkType));
    MOCK_METHOD3(AddLaneResourceToPool, int32_t (const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide));
    MOCK_METHOD2(DelLaneResourceByLaneId, int32_t (uint64_t laneId, bool isServerSide));
    MOCK_METHOD2(FindLaneResourceByLaneId, int32_t (uint64_t laneId, LaneResource *resourceItem));
    MOCK_METHOD3(FindLaneResourceByLinkType, int32_t (const char *peerUdid, LaneLinkType type, LaneResource *resource));
    MOCK_METHOD1(FreeLaneReqId, void (uint32_t laneReqId));
    MOCK_METHOD3(LaneInfoProcess, int32_t (const LaneLinkInfo *linkInfo, LaneConnInfo *connInfo,
        LaneProfile *profile));

    static int32_t BuildLinkSuccess(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *callback);
    static int32_t BuildLinkFail(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *callback);
};
} // namespace OHOS
#endif // LNN_CTRL_LANE_DEPS_MOCK_H
