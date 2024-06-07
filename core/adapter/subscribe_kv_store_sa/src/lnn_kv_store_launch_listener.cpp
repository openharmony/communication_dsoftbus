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

#include "lnn_kv_store_launch_listener.h"
#include "lnn_log.h"
#include "system_ability_definition.h"
#include "lnn_data_cloud_sync.h"

namespace OHOS {

void KvStoreStatusChangeListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId == DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID) {
        LNN_LOGI(LNN_LEDGER, "kv store SA launch.");
        LnnInitCloudSyncModule();
    }
}

void KvStoreStatusChangeListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    if (systemAbilityId == DISTRIBUTED_KV_DATA_SERVICE_ABILITY_ID) {
        LNN_LOGI(LNN_LEDGER, "kv store SA shutdown.");
    }
}

} // namespace OHOS
