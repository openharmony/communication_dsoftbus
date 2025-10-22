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

#ifndef TRANS_BUS_CENTER_MANAGER_MOCK_H
#define TRANS_BUS_CENTER_MANAGER_MOCK_H

#include <cstdint>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bus_center_manager.h"

namespace OHOS {
class TransBusCenterManagerInterface {
public:
    TransBusCenterManagerInterface() {};
    virtual ~TransBusCenterManagerInterface() {};
    virtual int32_t LnnGetRemoteNumInfo(const char *networkId, InfoKey key, int32_t *info) = 0;
};

class TransBusCenterManagerInterfaceMock : public TransBusCenterManagerInterface {
public:
    TransBusCenterManagerInterfaceMock();
    ~TransBusCenterManagerInterfaceMock() override;
    MOCK_METHOD3(LnnGetRemoteNumInfo, int32_t(const char *networkId, InfoKey key, int32_t *info));
};
} /* namespace OHOS */
#endif /* TRANS_BUS_CENTER_MANAGER_MOCK_H */
