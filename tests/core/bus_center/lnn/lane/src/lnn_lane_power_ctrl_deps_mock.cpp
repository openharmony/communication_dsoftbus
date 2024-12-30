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

#include "lnn_lane_power_ctrl_deps_mock.h"
#include "softbus_error_code.h"
#include "softbus_socket.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_lanePowerCtrlDepsInterface;

LanePowerCtrlDepsInterfaceMock::LanePowerCtrlDepsInterfaceMock()
{
    g_lanePowerCtrlDepsInterface = reinterpret_cast<void *>(this);
}

LanePowerCtrlDepsInterfaceMock::~LanePowerCtrlDepsInterfaceMock()
{
    g_lanePowerCtrlDepsInterface = nullptr;
}

static LanePowerCtrlDepsInterface *GetLanePowerCtrlDepsInterface()
{
    return reinterpret_cast<LanePowerCtrlDepsInterface *>(g_lanePowerCtrlDepsInterface);
}

extern "C" {
bool IsPowerControlEnabled(void)
{
    return GetLanePowerCtrlDepsInterface()->IsPowerControlEnabled();
}

int32_t EnablePowerControl(const WifiDirectLinkInfo *wifiDirectInfo)
{
    return GetLanePowerCtrlDepsInterface()->EnablePowerControl(wifiDirectInfo);
}

void DisablePowerControl(const WifiDirectLinkInfo *wifiDirectInfo)
{
    GetLanePowerCtrlDepsInterface()->DisablePowerControl(wifiDirectInfo);
}
}
} // namespace OHOS