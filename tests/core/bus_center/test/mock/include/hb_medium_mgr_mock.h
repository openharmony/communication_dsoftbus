/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef HB_MEDIUM_MGR_MOCK_H
#define HB_MEDIUM_MGR_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

namespace OHOS {
class HbMediumMgrExtInterface {
public:
    HbMediumMgrExtInterface() {};
    virtual ~HbMediumMgrExtInterface() {};
    virtual int32_t LnnStartSleOfflineTimingStrategy(const char *networkId) = 0;
};
class HbMediumMgrExtInterfaceMock : public HbMediumMgrExtInterface {
public:
    HbMediumMgrExtInterfaceMock();
    ~HbMediumMgrExtInterfaceMock() override;
    MOCK_METHOD1(LnnStartSleOfflineTimingStrategy, int32_t(const char *));
};
} // namespace OHOS
#endif // HB_MEDIUM_MGR_MOCK_H
