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

#ifndef PERMISSION_STATUS_CHANGE_CB_H
#define PERMISSION_STATUS_CHANGE_CB_H

#include "perm_state_change_callback_customize.h"
#include "ipc_skeleton.h"
#include "accesstoken_kit.h"

namespace OHOS {
using namespace Security::AccessToken;
class PermissionStatusChangeCb : public PermStateChangeCallbackCustomize {
public:
    PermissionStatusChangeCb(const PermStateChangeScope &scopeInfo, std::string _pkgName, int32_t _pid)
        : PermStateChangeCallbackCustomize(scopeInfo), pkgName(_pkgName), pid(_pid) {}
    ~PermissionStatusChangeCb(void) {}
    void PermStateChangeCallback(PermStateChangeInfo& result) override;
private:
    std::string pkgName;
    int32_t pid;
};

void RegisterDataSyncPermission(const uint32_t& callingTokenId,
                                const std::string& permissionName, const std::string& pkgName, int32_t pid);
} // namespace OHOS
#endif // PERMISSION_STATUS_CHANGE_CB_H