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

#include "softbus_os_account_adapter.h"
using namespace OHOS;

int32_t GetOsAccountLocalIdFromUidAdapter(const int32_t uid)
{
    int32_t appUserId = -1;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, appUserId);
    return appUserId;
}

int32_t IsOsAccountForegroundAdapter(const int32_t appUserId, bool &isForegroundUser)
{
    int32_t res = OHOS::AccountSA::OsAccountManager::IsOsAccountForeground(appUserId, isForegroundUser);
    return res;
}