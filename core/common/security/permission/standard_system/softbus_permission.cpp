/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "bundle_mgr_interface.h"
#include "ipc_skeleton.h"
#include "permission/permission.h"
#include "permission/permission_kit.h"
#include "permission_entry.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "sys_mgr_client.h"
#include "system_ability_definition.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::Security::Permission;

namespace {
    const std::string PERMISSION_JSON_FILE = "/system/etc/communication/softbus/softbus_trans_permission.json";
    const std::string SYSTEM_APP_PERMISSION = "com.huawei.permission.MANAGE_DISTRIBUTED_PERMISSION";
    const std::string DANGER_APP_PERMISSION = "ohos.permission.DISTRIBUTED_DATASYNC";
    const std::string BIND_DISCOVER_SERVICE = "com.huawei.hwddmp.permission.BIND_DISCOVER_SERVICE";
    const int32_t SYSTEM_UID = 1000;
    const int32_t MULTE_USER_RADIX = 100000;

#ifdef PERMISSION_TEST
    const int32_t TEST_UID = 1000;
    const int32_t TEST_PID = 1;
#endif

    int32_t CheckSystemPermission(const std::string &pkgName, const std::string &permission)
    {
        auto bundleObj =
        OHOS::DelayedSingleton<SysMrgClient>::GetInstance()->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (bundleObj == nullptr) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "failed to get bundle manager service");
            return SOFTBUS_ERR;
        }
        OHOS::sptr<IBundleMgr> bmgr = OHOS::iface_cast<IBundleMgr>(bundleObj);
        return bmgr->CheckPermission(std::string(pkgName), std::string(permission));
    }
}

int32_t TransPermissionInit()
{
    return LoadPermissionJson(PERMISSION_JSON_FILE.c_str());
}

void TransPermissionDeinit(void)
{
    DeinitPermissionJson();
}

int32_t CheckTransPermission(const char *sessionName, const char *pkgName, uint32_t actions)
{
    if (sessionName == nullptr || pkgName == nullptr) {
        return SOFTBUS_PERMISSION_DENIED;
    }
#ifdef PERMISSION_TEST
    int32_t callingUid = TEST_UID;
    int32_t callingPid = TEST_PID;
#else
    int32_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
    int32_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
#endif
    SoftBusPermissionItem *pItem = CreatePermissionItem(NATIVE_APP, callingUid, callingPid, pkgName, actions);
    if (pItem == nullptr) {
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = CheckPermissionEntry(sessionName, pItem);
    SoftBusFree(pItem);
    return ret;
}

bool CheckDiscPermission(const char *pkgName)
{
    std::string pkg;
    if (pkgName != nullptr) {
        pkg = std::string(pkgName);
    } else {
        return false;
    }
#ifdef PERMISSION_TEST
    int32_t callingUid = TEST_UID;
#else
    int32_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
#endif
    if (callingUid == SYSTEM_UID || callingUid % MULTE_USER_RADIX == SYSTEM_UID) {
        return true;
    }
    if (CheckSystemPermission(pkg, BIND_DISCOVER_SERVICE) == PERMISSION_GRANTED) {
        return true;
    }
    return false;
}

bool CheckBusCenterPermission(const char *pkgName)
{
    std::string pkg;
    if (pkgName != nullptr) {
        pkg = std::string(pkgName);
    } else {
        return false;
    }

#ifdef PERMISSION_TEST
    int32_t callingUid = TEST_UID;
#else
    int32_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
#endif
    if (callingUid == SYSTEM_UID || callingUid % MULTE_USER_RADIX == SYSTEM_UID) {
        return true;
    }
    if (CheckSystemPermission(pkg, SYSTEM_APP_PERMISSION) == PERMISSION_GRANTED) {
        return true;
    }
    if (CheckSystemPermission(pkg, DANGER_APP_PERMISSION) == PERMISSION_GRANTED) {
        return true;
    }
    return false;
}