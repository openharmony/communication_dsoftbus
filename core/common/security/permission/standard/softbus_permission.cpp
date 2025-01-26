/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "softbus_permission.h"

#include <sys/types.h>
#include <unistd.h>

#include "anonymizer.h"
#include "comm_log.h"
#include "ipc_skeleton.h"
#include "permission_entry.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "system_ability_definition.h"
#include "trans_session_manager.h"

namespace {
    const char *PERMISSION_JSON_FILE = "/system/etc/communication/softbus/softbus_trans_permission.json";
    const int32_t SYSTEM_UID = 1000;
    const int32_t MULTE_USER_RADIX = 100000;
}

int32_t TransPermissionInit(void)
{
    int32_t ret = LoadPermissionJson(PERMISSION_JSON_FILE);
    if (ret != SOFTBUS_OK) {
        COMM_LOGI(COMM_PERM, "load permission json fail");
        return ret;
    }
    return InitDynamicPermission();
}

void TransPermissionDeinit(void)
{
    DeinitPermissionJson();
}

int32_t CheckTransPermission(
    pid_t callingUid, pid_t callingPid, const char *pkgName, const char *sessionName, uint32_t actions)
{
    if (sessionName == nullptr || pkgName == nullptr) {
        COMM_LOGI(COMM_PERM, "invalid param");
        return SOFTBUS_PERMISSION_DENIED;
    }
    uint64_t callingFullTokenId = OHOS::IPCSkeleton::GetCallingFullTokenID();
    char *tmpName = nullptr;
    int32_t permType = SoftBusCalcPermType(callingFullTokenId, callingUid, callingPid);
    SoftBusPermissionItem *pItem = CreatePermissionItem(permType, callingUid, callingPid, pkgName, actions);
    if (pItem == nullptr) {
        COMM_LOGI(COMM_PERM, "pItem is null");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = CheckPermissionEntry(sessionName, pItem);
    SoftBusFree(pItem);
    if (ret >= SYSTEM_APP) {
        return SOFTBUS_OK;
    }
    Anonymize(sessionName, &tmpName);
    COMM_LOGE(COMM_PERM, "permission denied, permType=%{public}d, ret=%{public}d, sessionName=%{public}s, \
        callingUid=%{public}d, callingPid=%{public}d", permType, ret, tmpName, callingUid, callingPid);
    AnonymizeFree(tmpName);
    return SOFTBUS_PERMISSION_DENIED;
}

int32_t CheckTransSecLevel(const char *mySessionName, const char *peerSessionName)
{
    if (mySessionName == nullptr || peerSessionName == nullptr) {
        COMM_LOGI(COMM_PERM, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    if (strcmp(mySessionName, peerSessionName) == 0) {
        return SOFTBUS_OK;
    }
    if (!PermIsSecLevelPublic(mySessionName)) {
        COMM_LOGI(COMM_PERM, "mySessionName isn't seclevel");
        return SOFTBUS_PERMISSION_DENIED;
    }
    if (!PermIsSecLevelPublic(peerSessionName)) {
        COMM_LOGI(COMM_PERM, "peerSessionName isn't seclevel");
        return SOFTBUS_PERMISSION_DENIED;
    }
    return SOFTBUS_OK;
}

bool CheckDiscPermission(pid_t callingUid, const char *pkgName)
{
    std::string pkg = "";
    if (pkgName != nullptr) {
        pkg = std::string(pkgName);
    } else {
        return false;
    }
    if (callingUid == SYSTEM_UID || callingUid % MULTE_USER_RADIX == SYSTEM_UID) {
        return true;
    }
    return false;
}

bool CheckBusCenterPermission(pid_t callingUid, const char *pkgName)
{
    std::string pkg = "";
    if (pkgName != nullptr) {
        pkg = std::string(pkgName);
    } else {
        return false;
    }
    if (callingUid == SYSTEM_UID || callingUid % MULTE_USER_RADIX == SYSTEM_UID) {
        return true;
    }
    return false;
}

int32_t GrantTransPermission(int32_t callingUid, int32_t callingPid, const char *sessionName)
{
    if (sessionName == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    return AddDynamicPermission(callingUid, callingPid, sessionName);
}

int32_t RemoveTransPermission(const char *sessionName)
{
    if (sessionName == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    return DeleteDynamicPermission(sessionName);
}
