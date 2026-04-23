/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_heartbeat_constraint_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_lnnHeartbeatConstraintInterface;
LnnHeartbeatConstraintInterfaceMock::LnnHeartbeatConstraintInterfaceMock()
{
    g_lnnHeartbeatConstraintInterface = reinterpret_cast<void *>(this);
}

LnnHeartbeatConstraintInterfaceMock::~LnnHeartbeatConstraintInterfaceMock()
{
    g_lnnHeartbeatConstraintInterface = nullptr;
}

static LnnHeartbeatConstraintInterface *GetLnnHeartbeatConstraintInterface()
{
    return reinterpret_cast<LnnHeartbeatConstraintInterfaceMock *>(g_lnnHeartbeatConstraintInterface);
}

extern "C" {
int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetLnnHeartbeatConstraintInterface()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetLnnHeartbeatConstraintInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}

void LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType, DeviceLeaveReason reason)
{
    return GetLnnHeartbeatConstraintInterface()->LnnRequestLeaveSpecific(networkId, addrType, reason);
}

void AuthRemoveDeviceKeyByUdidPacked(const char *udid)
{
    return GetLnnHeartbeatConstraintInterface()->AuthRemoveDeviceKeyByUdidPacked(udid);
}

bool LnnIsOsAccountConstraint(void)
{
    return GetLnnHeartbeatConstraintInterface()->LnnIsOsAccountConstraint();
}

int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen, bool hasMcuRequestDisable)
{
    return GetLnnHeartbeatConstraintInterface()->LnnRequestLeaveByAddrType(type, typeLen, hasMcuRequestDisable);
}
}
} // namespace OHOS
