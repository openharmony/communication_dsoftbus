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
    MOCK_METHOD3(FindLaneResourceByLinkType, int32_t (const char *peerUdid, LaneLinkType type, LaneResource *resource));

    static int32_t ActionOfChannelOpenFailed(int32_t requestId, const char *networkId,
        const TransProxyPipelineChannelOption *option, const ITransProxyPipelineCallback *callback);
    static int32_t ActionOfChannelOpened(int32_t requestId, const char *networkId,
        const TransProxyPipelineChannelOption *option, const ITransProxyPipelineCallback *callback);
};
} // namespace OHOS
#endif // LNN_LANE_LINK_DEPS_MOCK_H
