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

#ifndef LNN_LANE_POWER_CTRL_DEPS_MOCK_H
#define LNN_LANE_POWER_CTRL_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "lnn_lane_power_control.h"

namespace OHOS {
class LanePowerCtrlDepsInterface {
public:
    LanePowerCtrlDepsInterface() {};
    virtual ~LanePowerCtrlDepsInterface() {};

    virtual bool IsPowerControlEnabled(void) = 0;
    virtual int32_t EnablePowerControl(const WifiDirectLinkInfo *wifiDirectInfo) = 0;
    virtual void DisablePowerControl(const WifiDirectLinkInfo *wifiDirectInfo) = 0;
};

class LanePowerCtrlDepsInterfaceMock : public LanePowerCtrlDepsInterface {
public:
    LanePowerCtrlDepsInterfaceMock();
    ~LanePowerCtrlDepsInterfaceMock() override;
    
    MOCK_METHOD0(IsPowerControlEnabled, bool (void));
    MOCK_METHOD1(EnablePowerControl, int32_t (const WifiDirectLinkInfo *wifiDirectInfo));
    MOCK_METHOD1(DisablePowerControl, void (const WifiDirectLinkInfo *wifiDirectInfo));
};
} // namespace OHOS
#endif // LNN_LANE_POWER_CTRL_DEPS_MOCK_H