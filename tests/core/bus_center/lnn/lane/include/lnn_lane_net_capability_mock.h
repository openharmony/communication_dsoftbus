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

#ifndef LNN_LANE_NET_CAPABILITY_MOCK_H
#define LNN_LANE_NET_CAPABILITY_MOCK_H

#include <gmock/gmock.h>

#include "lnn_lane_communication_capability.h"
#include "softbus_bus_center.h"

namespace OHOS {
class LaneNetCapInterface {
public:
    LaneNetCapInterface() {};
    virtual ~LaneNetCapInterface() {};

    virtual int32_t CheckStaticNetCap(const char *networkId, LaneLinkType linkType) = 0;
    virtual int32_t CheckDynamicNetCap(const char *networkId, LaneLinkType linkType) = 0;
    virtual void SetRemoteDynamicNetCap(const char *peerUdid, LaneLinkType linkType) = 0;
};

class LaneNetCapInterfaceMock : public LaneNetCapInterface {
public:
    LaneNetCapInterfaceMock();
    ~LaneNetCapInterfaceMock() override;

    MOCK_METHOD2(CheckStaticNetCap, int32_t (const char *networkId, LaneLinkType linkType));
    MOCK_METHOD2(CheckDynamicNetCap, int32_t (const char *networkId, LaneLinkType linkType));
    MOCK_METHOD2(SetRemoteDynamicNetCap, void (const char *peerUdid, LaneLinkType linkType));
};
} // namespace OHOS
#endif // LNN_LANE_NET_CAPABILITY_MOCK_H
