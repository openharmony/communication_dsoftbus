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

#include "comm_log.h"
#include "softbus_error_code.h"

extern "C" int32_t IsValidPkgName(int32_t uid, const char *pkgName)
{
    if (pkgName == NULL) {
        COMM_LOGI(COMM_PERM, "pkgName is null");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}
