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

#include "bus_center_decision_center_deps_mock.h"
#include "softbus_error_code.h"

using namespace testing::ext;
using namespace testing;

namespace OHOS {
void *g_busCenterDecisionCenterDepsInterface;
BusCenterDecisionCenterDepsInterfaceMock::BusCenterDecisionCenterDepsInterfaceMock()
{
    g_busCenterDecisionCenterDepsInterface = reinterpret_cast<void *>(this);
}

BusCenterDecisionCenterDepsInterfaceMock::~BusCenterDecisionCenterDepsInterfaceMock()
{
    g_busCenterDecisionCenterDepsInterface = nullptr;
}

static BusCenterDecisionCenterDepsInterface *GetBusCenterDecisionCenterDepsInterface()
{
    return reinterpret_cast<BusCenterDecisionCenterDepsInterface *>(g_busCenterDecisionCenterDepsInterface);
}

extern "C" {
SoftBusList *CreateSoftBusList()
{
    return GetBusCenterDecisionCenterDepsInterface()->CreateSoftBusList();
}
}
} // namespace OHOS
