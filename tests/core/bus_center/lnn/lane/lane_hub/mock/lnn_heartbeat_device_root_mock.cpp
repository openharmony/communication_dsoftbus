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

 /*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0g_ledger_Interface
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lnn_heartbeat_device_root_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_lnnHeatbeatStaticInterface;
LnnHeatbeatStaticInterfaceMock::LnnHeatbeatStaticInterfaceMock()
{
    g_lnnHeatbeatStaticInterface = reinterpret_cast<void *>(this);
}

LnnHeatbeatStaticInterfaceMock::~LnnHeatbeatStaticInterfaceMock()
{
    g_lnnHeatbeatStaticInterface = nullptr;
}

static LnnHeatbeatStaticInterface *GetLnnHeatbeatStaticInterface()
{
    return reinterpret_cast<LnnHeatbeatStaticInterfaceMock *>(g_lnnHeatbeatStaticInterface);
}

extern "C" {
int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType)
{
    return GetLnnHeatbeatStaticInterface()->LnnRequestLeaveSpecific(networkId, addrType);
}

int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum)
{
    return GetLnnHeatbeatStaticInterface()->LnnGetAllOnlineNodeInfo(info, infoNum);
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    return GetLnnHeatbeatStaticInterface()->LnnGetRemoteNodeInfoById(id, type, info);
}
}
} // namespace OHOS