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

#include "lnn_local_ledger_deps_mock.h"
#include "lnn_sle_capability_mock.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_lnnSleCapabilityInterface;

LnnSleCapabilityInterfaceMock::LnnSleCapabilityInterfaceMock()
{
    g_lnnSleCapabilityInterface = reinterpret_cast<void *>(this);
}

LnnSleCapabilityInterfaceMock::~LnnSleCapabilityInterfaceMock()
{
    g_lnnSleCapabilityInterface = nullptr;
}

static LnnSleCapabilityInterfaceMock *GetLnnSleCapabilityInterface()
{
    return reinterpret_cast<LnnSleCapabilityInterfaceMock *>(g_lnnSleCapabilityInterface);
}

extern "C" {
int32_t GetSleRangeCapacityPacked(void)
{
    return GetLnnSleCapabilityInterface()->GetSleRangeCapacityPacked();
}

int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info)
{
    return GetLnnSleCapabilityInterface()->LnnGetLocalNumInfo(key, info);
}

int32_t LnnUpdateSleCapacityAndVersion(int32_t slecap)
{
    return GetLnnSleCapabilityInterface()->LnnUpdateSleCapacityAndVersion(slecap);
}

bool IsSleEnabledPacked(void)
{
    return GetLnnSleCapabilityInterface()->IsSleEnabledPacked();
}

int32_t GetLocalSleAddrPacked(char *sleAddr, uint32_t sleAddrLen)
{
    return GetLnnSleCapabilityInterface()->GetLocalSleAddrPacked(sleAddr, sleAddrLen);
}

int32_t LnnSetLocalStrInfo(InfoKey key, const char *info)
{
    return GetLnnSleCapabilityInterface()->LnnSetLocalStrInfo(key, info);
}

cJSON *cJSON_CreateObject()
{
    return GetLnnSleCapabilityInterface()->cJSON_CreateObject();
}

bool AddNumberToJsonObject(cJSON *json, const char * const string, int32_t num)
{
    return GetLnnSleCapabilityInterface()->AddNumberToJsonObject(json, string, num);
}

bool AddStringToJsonObject(cJSON *json, const char * const string, const char *value)
{
    return GetLnnSleCapabilityInterface()->AddStringToJsonObject(json, string, value);
}

int32_t LnnRegSyncInfoHandler(LnnSyncInfoType type, LnnSyncInfoMsgHandler handler)
{
    return GetLnnSleCapabilityInterface()->LnnRegSyncInfoHandler(type, handler);
}

int32_t SoftBusAddSleStateListenerPacked(const SoftBusSleStateListener *listener, int32_t *listenerId)
{
    return GetLnnSleCapabilityInterface()->SoftBusAddSleStateListenerPacked(listener, listenerId);
}

int32_t LnnSetDLSleRangeInfo(const char *id, IdCategory type, int32_t sleCap, const char *addr)
{
    return GetLnnSleCapabilityInterface()->LnnSetDLSleRangeInfo(id, type, sleCap, addr);
}
} // extern "C"
} // namespace OHOS
