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

#ifndef LNN_LANE_SELECT_MOCK_H
#define LNN_LANE_SELECT_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

namespace OHOS {
class LaneSelectInterface {
public:
    LaneSelectInterface() {};
    virtual ~LaneSelectInterface() {};
    virtual uint64_t SoftBusGetSysTimeMs(void) = 0;
};

class LaneSelectInterfaceMock : public LaneSelectInterface {
public:
    LaneSelectInterfaceMock();
    ~LaneSelectInterfaceMock() override;
    MOCK_METHOD0(SoftBusGetSysTimeMs, uint64_t(void));
};
} // namespace OHOS
#endif // LNN_LANE_SELECT_MOCK_H