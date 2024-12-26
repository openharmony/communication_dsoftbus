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

#ifndef LNN_TRANS_LANE_DEPS_MOCK_H
#define LNN_TRANS_LANE_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "lnn_lane_common.h"
#include "lnn_lane_link.h"
#include "lnn_lane_model.h"
#include "lnn_lane_select.h"
#include "lnn_lane_reliability.h"

namespace OHOS {
class TransLaneDepsInterface {
public:
    TransLaneDepsInterface() {};
    virtual ~TransLaneDepsInterface() {};

    virtual int32_t SelectAuthLane(const char *networkId, LanePreferredLinkList *recommendList,
        LanePreferredLinkList *request) = 0;
    virtual int32_t SelectLane(const char *networkId, const LaneSelectParam *request,
        LanePreferredLinkList *recommendList, uint32_t *listNum);
    virtual int32_t SelectExpectLanesByQos(const char *networkId, const LaneSelectParam *request,
        LanePreferredLinkList *recommendList);
    virtual int32_t BuildLink(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *cb) = 0;
    virtual int32_t DestroyLink(const char *networkId, uint32_t laneReqId, LaneLinkType type) = 0;
    virtual uint32_t GenerateLaneProfileId(const LaneGenerateParam *param) = 0;
    virtual void UnbindLaneReqIdFromProfile(uint32_t laneReqId, uint32_t profileId) = 0;
    virtual int32_t BindLaneIdToProfile(uint64_t laneId, LaneProfile *profile) = 0;
    virtual int32_t AddLaneResourceToPool(const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide) = 0;
    virtual int32_t DelLaneResourceByLaneId(uint64_t laneId, bool isServerSide) = 0;
    virtual int32_t FindLaneResourceByLaneId(uint64_t laneId, LaneResource *resourceItem) = 0;
    virtual void FreeLaneReqId(uint32_t laneReqId) = 0;
    virtual int32_t AddLaneBusinessInfoItem(LaneType laneType, uint64_t laneId) = 0;
    virtual int32_t DelLaneBusinessInfoItem(LaneType laneType, uint64_t laneId) = 0;
    virtual int32_t LaneLinkupNotify(const char *peerUdid, const LaneLinkInfo *laneLinkInfo) = 0;
    virtual int32_t LaneLinkdownNotify(const char *peerUdid, const LaneLinkInfo *laneLinkInfo) = 0;
    virtual uint64_t GenerateLaneId(const char *localUdid, const char *remoteUdid, LaneLinkType linkType) = 0;
    virtual int32_t LaneCheckLinkValid(const char *networkId, LaneLinkType linkType, LaneTransType transType) = 0;
    virtual int32_t GetErrCodeOfLink(const char *networkId, LaneLinkType linkType) = 0;
    virtual int32_t CheckLaneResourceNumByLinkType(const char *peerUdid, LaneLinkType type, int32_t *laneNum) = 0;
    virtual void DetectEnableWifiDirectApply(void) = 0;
    virtual void DetectDisableWifiDirectApply(void) = 0;
    virtual int32_t CheckLinkConflictByReleaseLink(LaneLinkType releaseLink) = 0;
};

class TransLaneDepsInterfaceMock : public TransLaneDepsInterface {
public:
    TransLaneDepsInterfaceMock();
    ~TransLaneDepsInterfaceMock() override;
    MOCK_METHOD3(SelectAuthLane, int32_t (const char *, LanePreferredLinkList *, LanePreferredLinkList *));
    MOCK_METHOD4(SelectLane, int32_t (const char*, const LaneSelectParam *, LanePreferredLinkList *, uint32_t *));
    MOCK_METHOD3(SelectExpectLanesByQos, int32_t (const char*, const LaneSelectParam *, LanePreferredLinkList *));
    MOCK_METHOD3(BuildLink, int32_t (const LinkRequest *, uint32_t, const LaneLinkCb *));
    MOCK_METHOD3(DestroyLink, int32_t (const char *networkId, uint32_t laneReqId, LaneLinkType type));
    MOCK_METHOD1(GenerateLaneProfileId, uint32_t (const LaneGenerateParam *));
    MOCK_METHOD2(UnbindLaneReqIdFromProfile, void (uint32_t, uint32_t));
    MOCK_METHOD2(BindLaneIdToProfile, int32_t (uint64_t, LaneProfile *));
    MOCK_METHOD3(AddLaneResourceToPool, int32_t (const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide));
    MOCK_METHOD2(DelLaneResourceByLaneId, int32_t (uint64_t laneId, bool isServerSide));
    MOCK_METHOD2(FindLaneResourceByLaneId, int32_t (uint64_t laneId, LaneResource *resourceItem));
    MOCK_METHOD1(FreeLaneReqId, void (uint32_t laneReqId));
    MOCK_METHOD2(AddLaneBusinessInfoItem, int32_t (LaneType laneType, uint64_t laneId));
    MOCK_METHOD2(DelLaneBusinessInfoItem, int32_t (LaneType laneType, uint64_t laneId));
    MOCK_METHOD2(LaneLinkupNotify, int32_t (const char *peerUdid, const LaneLinkInfo *laneLinkInfo));
    MOCK_METHOD2(LaneLinkdownNotify, int32_t (const char *peerUdid, const LaneLinkInfo *laneLinkInfo));
    MOCK_METHOD3(GenerateLaneId, uint64_t (const char *localUdid, const char *remoteUdid, LaneLinkType linkType));
    MOCK_METHOD3(LaneCheckLinkValid, int32_t (const char *networkId, LaneLinkType linkType, LaneTransType transType));
    MOCK_METHOD2(GetErrCodeOfLink, int32_t (const char *networkId, LaneLinkType linkType));
    MOCK_METHOD3(CheckLaneResourceNumByLinkType, int32_t (const char *peerUdid, LaneLinkType type, int32_t *laneNum));
    MOCK_METHOD0(DetectEnableWifiDirectApply, void (void));
    MOCK_METHOD0(DetectDisableWifiDirectApply, void (void));
    MOCK_METHOD1(CheckLinkConflictByReleaseLink, int32_t (LaneLinkType releaseLink));

    static int32_t ActionOfLaneLinkSuccess(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *cb);
    static int32_t ActionOfLaneLinkFail(const LinkRequest *reqInfo, uint32_t reqId, const LaneLinkCb *cb);
};
} // namespace OHOS
#endif // LNN_TRANS_LANE_DEPS_MOCK_H