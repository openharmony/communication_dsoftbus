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

#ifndef BUS_CENTER_DECISION_CENTER_DEPS_MOCK_H
#define BUS_CENTER_DECISION_CENTER_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "softbus_utils.h"

namespace OHOS {
class BusCenterDecisionCenterDepsInterface {
public:
    BusCenterDecisionCenterDepsInterface() {};
    virtual ~BusCenterDecisionCenterDepsInterface() {};

    virtual SoftBusList *CreateSoftBusList() = 0;
};

class BusCenterDecisionCenterDepsInterfaceMock : public BusCenterDecisionCenterDepsInterface {
public:
    BusCenterDecisionCenterDepsInterfaceMock();
    ~BusCenterDecisionCenterDepsInterfaceMock() override;

    MOCK_METHOD0(CreateSoftBusList, SoftBusList * ());
};
} // namespace OHOS
#endif // BUS_CENTER_DECISION_CENTER_DEPS_MOCK_H
