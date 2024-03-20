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

#ifndef LNN_PARAM_UTILS_MOCK_H
#define LNN_PARAM_UTILS_MOCK_H

#include <gmock/gmock.h>

#include "lnn_lane_select.h"
#include "lnn_parameter_utils.h"

namespace OHOS {
class TransParameterUtilsDepsInterface {
public:
    TransParameterUtilsDepsInterface() {};
    virtual ~TransParameterUtilsDepsInterface() {};

    virtual int32_t SelectExpectLaneByParameter(LanePreferredLinkList *setRecommendLinkList) = 0;
    virtual bool IsLinkEnabled(LaneLinkType parameter) = 0;
};

class TransParameterUtilsDepsInterfaceMock : public TransParameterUtilsDepsInterface {
public:
    TransParameterUtilsDepsInterfaceMock();
    ~TransParameterUtilsDepsInterfaceMock() override;
    MOCK_METHOD1(SelectExpectLaneByParameter, int32_t (LanePreferredLinkList *));
    MOCK_METHOD1(IsLinkEnabled, bool (LaneLinkType));
};
} // namespace OHOS
#endif // LNN_PARAM_UTILS_MOCK_H