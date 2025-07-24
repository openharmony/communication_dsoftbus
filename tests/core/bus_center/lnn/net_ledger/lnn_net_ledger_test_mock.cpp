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

#include "lnn_net_ledger_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_lnnNetLedgerInterface;

LnnNetLedgerInterfaceMock::LnnNetLedgerInterfaceMock()
{
    g_lnnNetLedgerInterface = reinterpret_cast<void *>(this);
}

LnnNetLedgerInterfaceMock::~LnnNetLedgerInterfaceMock()
{
    g_lnnNetLedgerInterface = nullptr;
}

static LnnNetLedgerInterfaceMock *GetLnnNetLedgerInterface()
{
    return reinterpret_cast<LnnNetLedgerInterfaceMock *>(g_lnnNetLedgerInterface);
}

extern "C" {
int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info)
{
    return GetLnnNetLedgerInterface()->LnnGetLocalNumU64Info(key, info);
}

int32_t LnnSetLocalNum64Info(InfoKey key, int64_t info)
{
    return GetLnnNetLedgerInterface()->LnnSetLocalNum64Info(key, info);
}

bool IsSupportLpFeaturePacked(void)
{
    return GetLnnNetLedgerInterface()->IsSupportLpFeaturePacked();
}

bool LnnIsSupportLpSparkFeaturePacked(void)
{
    return GetLnnNetLedgerInterface()->LnnIsSupportLpSparkFeaturePacked();
}

int32_t LnnClearFeatureCapability(uint64_t *feature, FeatureCapability capaBit)
{
    return GetLnnNetLedgerInterface()->LnnClearFeatureCapability(feature, capaBit);
}
} // extern "C"
} // namespace OHOS