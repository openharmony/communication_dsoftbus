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

#include "permission_utils.h"

#include "bundle_mgr_interface.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "sys_mgr_client.h"
#include "system_ability_definition.h"

using namespace OHOS::AppExecFwk;

extern "C" int32_t IsValidPkgName(int32_t uid, const char *pkgName)
{
    if (pkgName == NULL) {
        return SOFTBUS_ERR;
    }
    auto bundleObj =
    OHOS::DelayedSingleton<SysMrgClient>::GetInstance()->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleObj == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "failed to get bundle manager service");
        return SOFTBUS_ERR;
    }
    OHOS::sptr<IBundleMgr> bmgr = OHOS::iface_cast<IBundleMgr>(bundleObj);
    std::string bundleName;
#ifndef PERMISSION_TEST
    bmgr->GetBundleNameForUid(uid, bundleName);
    printf("BundleName: %s\n", bundleName.c_str());
    if (std::string(pkgName) != bundleName) {
        return SOFTBUS_ERR;
    }
#endif
    return SOFTBUS_OK;
}