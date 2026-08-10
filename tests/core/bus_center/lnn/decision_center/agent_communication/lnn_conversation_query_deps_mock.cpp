/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "lnn_conversation_query_deps_mock.h"

#include "softbus_error_code.h"

namespace OHOS {
void *g_lnnConvQueryDepsInterface;

LnnConvQueryDepsInterfaceMock::LnnConvQueryDepsInterfaceMock()
{
    g_lnnConvQueryDepsInterface = reinterpret_cast<void *>(this);
}

LnnConvQueryDepsInterfaceMock::~LnnConvQueryDepsInterfaceMock()
{
    g_lnnConvQueryDepsInterface = nullptr;
}

static LnnConvQueryDepsInterface *GetConvQueryDepsInterface()
{
    return reinterpret_cast<LnnConvQueryDepsInterface *>(g_lnnConvQueryDepsInterface);
}
} // namespace OHOS

extern "C" {
int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info)
{
    auto *m = OHOS::GetConvQueryDepsInterface();
    return m ? m->LnnGetLocalNodeInfoSafe(info) : SOFTBUS_NOT_FIND;
}

int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info)
{
    auto *m = OHOS::GetConvQueryDepsInterface();
    return m ? m->LnnGetRemoteNodeInfoById(id, type, info) : SOFTBUS_NOT_FIND;
}

int32_t LnnRetrieveDeviceInfoByNetworkIdPacked(const char *networkId, NodeInfo *info)
{
    auto *m = OHOS::GetConvQueryDepsInterface();
    return m ? m->LnnRetrieveDeviceInfoByNetworkIdPacked(networkId, info) : SOFTBUS_NOT_FIND;
}

int32_t LnnRetrieveDeviceInfoByUdidPacked(const char *udid, NodeInfo *deviceInfo)
{
    auto *m = OHOS::GetConvQueryDepsInterface();
    return m ? m->LnnRetrieveDeviceInfoByUdidPacked(udid, deviceInfo) : SOFTBUS_NOT_FIND;
}

bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit)
{
    auto *m = OHOS::GetConvQueryDepsInterface();
    return m ? m->IsFeatureSupport(feature, capaBit) : false;
}

bool LnnGetOnlineStateById(const char *id, IdCategory type)
{
    auto *m = OHOS::GetConvQueryDepsInterface();
    return m ? m->LnnGetOnlineStateById(id, type) : false;
}

int32_t JudgeDeviceTypeAndGetOsAccountIds(void)
{
    auto *m = OHOS::GetConvQueryDepsInterface();
    return m ? m->JudgeDeviceTypeAndGetOsAccountIds() : 0;
}

int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info)
{
    auto *m = OHOS::GetConvQueryDepsInterface();
    return m ? m->LnnGetLocalNum64Info(key, info) : SOFTBUS_NOT_FIND;
}

bool LnnIsDefaultOhosAccount(void)
{
    auto *m = OHOS::GetConvQueryDepsInterface();
    return m ? m->LnnIsDefaultOhosAccount() : false;
}
}
