/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "comm_log.h"
#include "permission_status_change_cb.h"
#include "trans_client_proxy.h"
#include "softbus_errcode.h"
#include "message_parcel.h"

namespace OHOS {
void PermissionStatusChangeCb::PermStateChangeCallback(PermStateChangeInfo& result)
{
    COMM_LOGI(COMM_PERM, "permission changed. permissionName=%{public}s", result.permissionName.c_str());
    if (InformPermissionChange(result.permStateChangeType, this->pkgName.c_str(), pid) != SOFTBUS_OK) {
        COMM_LOGE(COMM_PERM, "InformPermissionChange fail");
    }
}

void RegisterDataSyncPermission(const uint32_t& callingTokenId,
                                const std::string& permissionName, const std::string& pkgName, int32_t pid)
{
    PermStateChangeScope scopeInfo;
    scopeInfo.permList = {permissionName};
    scopeInfo.tokenIDs = {callingTokenId};
    std::shared_ptr<PermissionStatusChangeCb> callbackPtr_ =
        std::make_shared<PermissionStatusChangeCb>(scopeInfo, pkgName, pid);
    COMM_LOGI(COMM_PERM, "after register. tokenId=%{public}d", callingTokenId);
    if (AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr_) != SOFTBUS_OK) {
        COMM_LOGE(COMM_PERM, "RegisterPermStateChangeCallback failed.");
    }
}
} // namespace OHOS