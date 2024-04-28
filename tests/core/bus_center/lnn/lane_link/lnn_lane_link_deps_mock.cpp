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
#include "softbus_error_code.h"

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

int32_t LaneLinkDepsInterfaceMock::ActionOfChannelOpenFailed(int32_t requestId, const char *networkId,
    const TransProxyPipelineChannelOption *option, const ITransProxyPipelineCallback *callback)
{
    callback->onChannelOpenFailed(requestId, SOFTBUS_ERR);
    return SOFTBUS_OK;
}

int32_t LaneLinkDepsInterfaceMock::ActionOfChannelOpened(int32_t requestId, const char *networkId,
    const TransProxyPipelineChannelOption *option, const ITransProxyPipelineCallback *callback)
{
    callback->onChannelOpened(requestId, 1);
    return SOFTBUS_OK;
}

extern "C" {
int32_t GetTransReqInfoByLaneReqId(uint32_t laneReqId, TransOption *reqInfo)
{
    return GetLaneLinkDepsInterface()->GetTransReqInfoByLaneReqId(laneReqId, reqInfo);
}

int32_t TransProxyPipelineGenRequestId(void)
{
    return GetLaneLinkDepsInterface()->TransProxyPipelineGenRequestId();
}

int32_t TransProxyPipelineOpenChannel(int32_t requestId, const char *networkId,
    const TransProxyPipelineChannelOption *option, const ITransProxyPipelineCallback *callback)
{
    return GetLaneLinkDepsInterface()->TransProxyPipelineOpenChannel(requestId, networkId, option, callback);
}

int32_t TransProxyPipelineCloseChannel(int32_t channelId)
{
    return GetLaneLinkDepsInterface()->TransProxyPipelineCloseChannel(channelId);
}

int32_t TransProxyPipelineCloseChannelDelay(int32_t channelId)
{
    return GetLaneLinkDepsInterface()->TransProxyPipelineCloseChannelDelay(channelId);
}

int32_t FindLaneResourceByLinkType(const char *peerUdid, LaneLinkType type, LaneResource *resource)
{
    return GetLaneLinkDepsInterface()->FindLaneResourceByLinkType(peerUdid, type, resource);
}
}
} // namespace OHOS
