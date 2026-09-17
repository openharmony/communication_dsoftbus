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

#include "hb_medium_mgr_mock.h"
#include "lnn_local_net_ledger.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_hbMediumMgrExtInterface = nullptr;
HbMediumMgrExtInterfaceMock::HbMediumMgrExtInterfaceMock()
{
    g_hbMediumMgrExtInterface = reinterpret_cast<void *>(this);
}

HbMediumMgrExtInterfaceMock::~HbMediumMgrExtInterfaceMock()
{
    g_hbMediumMgrExtInterface = nullptr;
}

static HbMediumMgrExtInterface *HbMediumMgrExtInterface()
{
    return reinterpret_cast<HbMediumMgrExtInterfaceMock *>(g_hbMediumMgrExtInterface);
}

extern "C" {
int32_t LnnStartSleOfflineTimingStrategy(const char *networkId)
{
    return HbMediumMgrExtInterface()->LnnStartSleOfflineTimingStrategy(networkId);
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    (void)json;
    (void)string;
    (void)value;
    return true;
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    (void)json;
    (void)string;
    (void)num;
    return true;
}

int32_t JudgeDeviceTypeAndGetOsAccountIds(void)
{
    return 0;
}

bool LnnIsCommandCbRegistered(void)
{
    return false;
}

const char *LnnGetCommandPkgName(void)
{
    return "ohos.distributedhardware.devicemanager";
}
}
} // namespace OHOS
