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

#ifndef LNN_FEATURE_CAPABILITY_MOCK_H
#define LNN_FEATURE_CAPABILITY_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "softbus_config_type.h"

namespace OHOS {
class LnnFeatureCapabilityInterface {
public:
    LnnFeatureCapabilityInterface() {};
    virtual ~LnnFeatureCapabilityInterface() {};

    virtual int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len) = 0;
    virtual bool IsSparkGroupEnabledPacked(void) = 0;
};
class LnnFeatureCapabilityInterfaceMock : public LnnFeatureCapabilityInterface {
public:
    LnnFeatureCapabilityInterfaceMock();
    ~LnnFeatureCapabilityInterfaceMock() override;
    MOCK_METHOD3(SoftbusGetConfig, int32_t(ConfigType type, unsigned char *val, uint32_t len));
    MOCK_METHOD0(IsSparkGroupEnabledPacked, bool());
};
} // namespace OHOS
#endif // LNN_FEATURE_CAPABILITY_MOCK_H
