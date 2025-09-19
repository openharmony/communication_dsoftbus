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

#include "bus_center_manager.h"

#include <securec.h>

#include "lnn_bus_center_ipc.h"
#include "lnn_event.h"
#include "lnn_log.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"
#include "wifi_direct_manager.h"

static void OnGroupStateChange(int32_t retCode)
{
    LnnIpcNotifyOnGroupStateChange(retCode);
}

int32_t LnnCreateGroupOwner(const char *pkgName, const struct GroupOwnerConfig *config,
    struct GroupOwnerResult *result)
{
    return GetWifiDirectManager()->connCreateGroupOwner(pkgName, config, result, OnGroupStateChange);
}

void LnnDestroyGroupOwner(const char *pkgName)
{
    GetWifiDirectManager()->connDestroyGroupOwner(pkgName);
}
