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

#include "hb_ctrl_deps_mock.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_hbCtrlDepsInterface;
HeartBeatCtrlDepsInterfaceMock::HeartBeatCtrlDepsInterfaceMock()
{
    g_hbCtrlDepsInterface = reinterpret_cast<void *>(this);
}

HeartBeatCtrlDepsInterfaceMock::~HeartBeatCtrlDepsInterfaceMock()
{
    g_hbCtrlDepsInterface = nullptr;
}

static HeartBeatCtrlDepsInterface *HeartBeatCtrlDepsInterface()
{
    return reinterpret_cast<HeartBeatCtrlDepsInterfaceMock *>(g_hbCtrlDepsInterface);
}

extern "C" {
void LnnNotifyNetworkStateChanged(SoftBusNetworkState state)
{
    return HeartBeatCtrlDepsInterface()->LnnNotifyNetworkStateChanged(state);
}

int32_t AuthFlushDevice(const char *uuid)
{
    return HeartBeatCtrlDepsInterface()->AuthFlushDevice(uuid);
}

int SoftBusGetBtState(void)
{
    return HeartBeatCtrlDepsInterface()->SoftBusGetBtState();
}

void RestartCoapDiscovery(void)
{
    return HeartBeatCtrlDepsInterface()->RestartCoapDiscovery();
}

ConnectionAddrType LnnConvertHbTypeToConnAddrType(LnnHeartbeatType type)
{
    return HeartBeatCtrlDepsInterface()->LnnConvertHbTypeToConnAddrType(type);
}

bool IsEnableSoftBusHeartbeat(void)
{
    return HeartBeatCtrlDepsInterface()->IsEnableSoftBusHeartbeat();
}

void LnnUpdateOhosAccount(void)
{
    return HeartBeatCtrlDepsInterface()->LnnUpdateOhosAccount();
}

int32_t LnnHbMediumMgrSetParam(const LnnHeartbeatMediumParam *param)
{
    return HeartBeatCtrlDepsInterface()->LnnHbMediumMgrSetParam(param);
}
}
} // namespace OHOS
