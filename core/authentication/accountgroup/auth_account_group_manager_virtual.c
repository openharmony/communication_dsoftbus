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

#include "auth_account_group_manager.h"

#include "softbus_error_code.h"

void RegisterAccountAuth(IAccountAuthCallback *cb)
{
    (void)cb;
    return;
}

int32_t StartGroupAccountAuth(const char *pkgName, int64_t requestId, const char *serviceId)
{
    (void)pkgName;
    (void)requestId;
    (void)serviceId;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t ProcessGroupAccountAuth(const char *pkgName, int64_t requestId, const uint8_t *data, uint32_t dataLen)
{
    (void)pkgName;
    (void)requestId;
    (void)data;
    (void)dataLen;
    return SOFTBUS_NOT_IMPLEMENT;
}
