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

#include <cstdint>
#include <securec.h>

#include "lnn_feature_capability_mock.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_lnnFeatureCapabilityInterface;

LnnFeatureCapabilityInterfaceMock::LnnFeatureCapabilityInterfaceMock()
{
    g_lnnFeatureCapabilityInterface = reinterpret_cast<void *>(this);
}

LnnFeatureCapabilityInterfaceMock::~LnnFeatureCapabilityInterfaceMock()
{
    g_lnnFeatureCapabilityInterface = nullptr;
}

static LnnFeatureCapabilityInterfaceMock *GetLnnFeatureCapabilityInterface()
{
    return reinterpret_cast<LnnFeatureCapabilityInterfaceMock *>(g_lnnFeatureCapabilityInterface);
}

extern "C" {
int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len)
{
    return GetLnnFeatureCapabilityInterface()->SoftbusGetConfig(type, val, len);
}

bool IsSparkGroupEnabledPacked(void)
{
    return GetLnnFeatureCapabilityInterface()->IsSparkGroupEnabledPacked();
}
} // extern "C"
} // namespace OHOS
