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

#include "lnn_kv_adapter_wrapper_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_kvAdapterInterface;
LnnKvAdapterInterfaceMock::LnnKvAdapterInterfaceMock()
{
    g_kvAdapterInterface = reinterpret_cast<void *>(this);
}

LnnKvAdapterInterfaceMock::~LnnKvAdapterInterfaceMock()
{
    g_kvAdapterInterface = nullptr;
}

static LnnKvAdapterInterface *GetKvAdapterInterface()
{
    return reinterpret_cast<LnnKvAdapterInterface *>(g_kvAdapterInterface);
}

extern "C" {
int32_t LnnCreateKvAdapter(int32_t *dbId, const char *appId, int32_t appIdLen, const char *storeId, int32_t storeIdLen)
{
    return GetKvAdapterInterface()->LnnCreateKvAdapter(dbId, appId, appIdLen, storeId, storeIdLen);
}

int32_t LnnDestroyKvAdapter(int32_t dbId)
{
    return GetKvAdapterInterface()->LnnDestroyKvAdapter(dbId);
}

void LnnRegisterDataChangeListener(
    int32_t dbId, const char *appId, int32_t appIdLen, const char *storeId, int32_t storeIdLen)
{
    return GetKvAdapterInterface()->LnnRegisterDataChangeListener(dbId, appId, appIdLen, storeId, storeIdLen);
}

void LnnUnRegisterDataChangeListener(int32_t dbId)
{
    return GetKvAdapterInterface()->LnnUnRegisterDataChangeListener(dbId);
}

int32_t LnnPutDBData(int32_t dbId, const char *key, int32_t keyLen, const char *value, int32_t valueLen)
{
    return GetKvAdapterInterface()->LnnPutDBData(dbId, key, keyLen, value, valueLen);
}

int32_t LnnDeleteDBDataByPrefix(int32_t dbId, const char *keyPrefix, int32_t keyPrefixLen)
{
    return GetKvAdapterInterface()->LnnDeleteDBDataByPrefix(dbId, keyPrefix, keyPrefixLen);
}

int32_t LnnCloudSync(int32_t dbId)
{
    return GetKvAdapterInterface()->LnnCloudSync(dbId);
}

int32_t LnnSetCloudAbilityInner(int32_t dbId, const bool isEnableCloud)
{
    return GetKvAdapterInterface()->LnnSetCloudAbilityInner(dbId, isEnableCloud);
}
}
} // namespace OHOS