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

#ifndef LNN_LANE_LINK_DEPS_MOCK_H
#define LNN_LANE_LINK_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "lnn_lane_link.h"
#include "lnn_lane_link_conflict.h"
#include "softbus_proxychannel_pipeline.h"

namespace OHOS {
class LaneLinkDepsInterface {
public:
    LaneLinkDepsInterface() {};
    virtual ~LaneLinkDepsInterface() {};

    virtual int32_t GetTransReqInfoByLaneReqId(uint32_t laneReqId, TransOption *reqInfo) = 0;
    virtual int32_t TransProxyPipelineGenRequestId(void) = 0;
    virtual int32_t TransProxyPipelineOpenChannel(int32_t requestId, const char *networkId,
        const TransProxyPipelineChannelOption *option, const ITransProxyPipelineCallback *callback) = 0;
    virtual int32_t TransProxyPipelineCloseChannel(int32_t channelId) = 0;
    virtual int32_t TransProxyPipelineCloseChannelDelay(int32_t channelId) = 0;
    virtual int32_t FindLaneResourceByLinkType(const char *peerUdid, LaneLinkType type, LaneResource *resource) = 0;
    virtual int32_t LaneDetectReliability(uint32_t laneReqId, const LaneLinkInfo *linkInfo,
        const LaneLinkCb *callback) = 0;
    virtual int32_t FindLaneResourceByLaneId(uint64_t laneId, LaneResource *resource) = 0;
    virtual int32_t InitLaneLink(void) = 0;
    virtual int32_t AddLaneResourceToPool(const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide) = 0;
    virtual int32_t DelLaneResourceByLaneId(uint64_t laneId, bool isServerSide) = 0;
    virtual void NotifyFreeLaneResult(uint32_t laneReqId, int32_t errCode) = 0;
    virtual LinkConflictType GetConflictTypeWithErrcode(int32_t conflictErrcode) = 0;
    virtual int32_t FindLinkConflictInfoByDevId(const DevIdentifyInfo *inputInfo, LinkConflictType conflictType,
        LinkConflictInfo *outputInfo) = 0;
    virtual void RemoveConflictInfoTimelinessMsg(const DevIdentifyInfo *inputInfo, LinkConflictType conflictType) = 0;
    virtual int32_t DelLinkConflictInfo(const DevIdentifyInfo *inputInfo, LinkConflictType conflictType) = 0;
    virtual int32_t ClearLaneResourceByLaneId(uint64_t laneId) = 0;
    virtual void RemoveDelayDestroyMessage(uint64_t laneId) = 0;
    virtual void DelLogicAndLaneRelationship(uint64_t laneId) = 0;
    virtual int32_t LnnSyncPtk(const char *networkId) = 0;
    virtual int32_t CheckLinkConflictByReleaseLink(LaneLinkType releaseLink) = 0;
};

class LaneLinkDepsInterfaceMock : public LaneLinkDepsInterface {
public:
    LaneLinkDepsInterfaceMock();
    ~LaneLinkDepsInterfaceMock() override;

    MOCK_METHOD2(GetTransReqInfoByLaneReqId, int32_t (uint32_t laneReqId, TransOption *reqInfo));
    MOCK_METHOD0(TransProxyPipelineGenRequestId, int32_t (void));
    MOCK_METHOD4(TransProxyPipelineOpenChannel, int32_t (int32_t requestId, const char *networkId,
        const TransProxyPipelineChannelOption *option, const ITransProxyPipelineCallback *callback));
    MOCK_METHOD1(TransProxyPipelineCloseChannel, int32_t (int32_t channelId));
    MOCK_METHOD1(TransProxyPipelineCloseChannelDelay, int32_t (int32_t channelId));
    MOCK_METHOD3(FindLaneResourceByLinkType, int32_t (const char *peerUdid, LaneLinkType type,
        LaneResource *resource));
    MOCK_METHOD3(LaneDetectReliability, int32_t (uint32_t laneReqId, const LaneLinkInfo *linkInfo,
        const LaneLinkCb *callback));
    MOCK_METHOD2(FindLaneResourceByLaneId, int32_t (uint64_t laneId, LaneResource *resource));
    MOCK_METHOD0(InitLaneLink, int32_t (void));
    MOCK_METHOD3(AddLaneResourceToPool, int32_t (const LaneLinkInfo *linkInfo, uint64_t laneId, bool isServerSide));
    MOCK_METHOD2(DelLaneResourceByLaneId, int32_t (uint64_t laneId, bool isServerSide));
    MOCK_METHOD2(NotifyFreeLaneResult, void (uint32_t laneReqId, int32_t errCode));
    MOCK_METHOD1(GetConflictTypeWithErrcode, LinkConflictType (int32_t conflictErrcode));
    MOCK_METHOD3(FindLinkConflictInfoByDevId, int32_t (const DevIdentifyInfo *inputInfo,
        LinkConflictType conflictType, LinkConflictInfo *outputInfo));
    MOCK_METHOD2(RemoveConflictInfoTimelinessMsg, void (const DevIdentifyInfo *inputInfo,
        LinkConflictType conflictType));
    MOCK_METHOD2(DelLinkConflictInfo, int32_t (const DevIdentifyInfo *inputInfo, LinkConflictType conflictType));
    MOCK_METHOD1(ClearLaneResourceByLaneId, int32_t (uint64_t laneId));
    MOCK_METHOD1(RemoveDelayDestroyMessage, void (uint64_t laneId));
    MOCK_METHOD1(DelLogicAndLaneRelationship, void (uint64_t laneId));
    MOCK_METHOD1(LnnSyncPtk, int32_t (const char *networkId));
    MOCK_METHOD1(CheckLinkConflictByReleaseLink, int32_t (LaneLinkType releaseLink));

    static int32_t ActionOfChannelOpenFailed(int32_t requestId, const char *networkId,
        const TransProxyPipelineChannelOption *option, const ITransProxyPipelineCallback *callback);
    static int32_t ActionOfChannelOpened(int32_t requestId, const char *networkId,
        const TransProxyPipelineChannelOption *option, const ITransProxyPipelineCallback *callback);
    static int32_t ActionOfDetectSuccess(uint32_t laneReqId, const LaneLinkInfo *linkInfo,
        const LaneLinkCb *callback);
    static int32_t ActionOfDetectFail(uint32_t laneReqId, const LaneLinkInfo *linkInfo,
        const LaneLinkCb *callback);
};
} // namespace OHOS
#endif // LNN_LANE_LINK_DEPS_MOCK_H
