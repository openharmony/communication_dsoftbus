/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "lnn_ohos_account_adapter.h"
#include "softbus_error_code.h"
#define ACCOUNT_ID 1

int32_t GetOsAccountId(char *id, uint32_t idLen, uint32_t *len)
{
    (void)id;
    (void)idLen;
    (void)len;
    return SOFTBUS_OK;
}

int32_t GetOsAccountIdByUserId(int32_t userId, char **id, uint32_t *len)
{
    (void)userId;
    (void)id;
    (void)len;
    return SOFTBUS_OK;
}

int32_t GetCurrentAccount(int64_t *account)
{
    (void)account;
    return SOFTBUS_OK;
}

int32_t GetActiveOsAccountIds(void)
{
    return ACCOUNT_ID;
}

bool IsActiveOsAccountUnlocked(void)
{
    return true;
}

int32_t GetOsAccountUid(char *id, uint32_t idLen, uint32_t *len)
{
    (void)id;
    (void)idLen;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}