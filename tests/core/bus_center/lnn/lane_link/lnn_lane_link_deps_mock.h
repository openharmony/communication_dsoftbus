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

#include "lnn_lane_assign.h"

namespace OHOS {
class LaneLinkDepsInterface {
public:
    LaneLinkDepsInterface() {};
    virtual ~LaneLinkDepsInterface() {};

    virtual int32_t GetTransOptionByLaneId(uint32_t laneId, TransOption *reqInfo) = 0;
};

class LaneLinkDepsInterfaceMock : public LaneLinkDepsInterface {
public:
    LaneLinkDepsInterfaceMock();
    ~LaneLinkDepsInterfaceMock() override;

    MOCK_METHOD2(GetTransOptionByLaneId, int32_t (uint32_t laneId, TransOption *reqInfo));
};
} // namespace OHOS
#endif // LNN_LANE_LINK_DEPS_MOCK_H
