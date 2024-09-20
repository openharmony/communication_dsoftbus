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

#ifndef LNN_LANE_HUB_DEPS_MOCK_H
#define LNN_LANE_HUB_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "lnn_lane_hub.h"

namespace OHOS {
class LaneHubDepsInterface {
public:
    LaneHubDepsInterface() {};
    virtual ~LaneHubDepsInterface() {};

    virtual int32_t InitLane(void) = 0;
    virtual int32_t LnnInitQos(void) = 0;
    virtual int32_t LnnInitTimeSync(void) = 0;
    virtual int32_t LnnInitHeartbeat(void) = 0;
    virtual int32_t LnnStartHeartbeatFrameDelay(void) = 0;
    virtual void LnnDeinitQos(void) = 0;
    virtual void DeinitLane(void) = 0;
    virtual void LnnDeinitTimeSync(void) = 0;
    virtual void LnnDeinitHeartbeat(void) = 0;
};

class LaneHubDepsInterfaceMock : public LaneHubDepsInterface {
public:
    LaneHubDepsInterfaceMock();
    ~LaneHubDepsInterfaceMock() override;

    MOCK_METHOD0(InitLane, int32_t (void));
    MOCK_METHOD0(LnnInitQos, int32_t (void));
    MOCK_METHOD0(LnnInitTimeSync, int32_t (void));
    MOCK_METHOD0(LnnInitHeartbeat, int32_t (void));
    MOCK_METHOD0(LnnStartHeartbeatFrameDelay, int32_t (void));
    MOCK_METHOD0(LnnDeinitQos, void (void));
    MOCK_METHOD0(DeinitLane, void (void));
    MOCK_METHOD0(LnnDeinitTimeSync, void (void));
    MOCK_METHOD0(LnnDeinitHeartbeat, void (void));
};
} // namespace OHOS
#endif // LNN_LANE_LINK_DEPS_MOCK_H
