/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "lnn_heartbeat_device_risk_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_lnnHeatbeatDeviceRiskInterface;
LnnHeatbeatDeviceRiskInterfaceMock::LnnHeatbeatDeviceRiskInterfaceMock()
{
    g_lnnHeatbeatDeviceRiskInterface = reinterpret_cast<void *>(this);
}

LnnHeatbeatDeviceRiskInterfaceMock::~LnnHeatbeatDeviceRiskInterfaceMock()
{
    g_lnnHeatbeatDeviceRiskInterface = nullptr;
}

static LnnHeatbeatDeviceRiskInterface *GetLnnHeatbeatDeviceRiskInterface()
{
    return reinterpret_cast<LnnHeatbeatDeviceRiskInterfaceMock *>(g_lnnHeatbeatDeviceRiskInterface);
}

extern "C" {
int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType, DeviceLeaveReason leaveReason)
{
    return GetLnnHeatbeatDeviceRiskInterface()->LnnRequestLeaveSpecific(networkId, addrType, leaveReason);
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetLnnHeatbeatDeviceRiskInterface()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetLnnHeatbeatDeviceRiskInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}
}
} // namespace OHOS