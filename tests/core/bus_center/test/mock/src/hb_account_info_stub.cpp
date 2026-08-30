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

#include "lnn_distributed_user_info.h"
#include "lnn_ohos_account.h"
#include "lnn_ohos_account_adapter.h"

#include "softbus_error_code.h"

int32_t GetAllForegroundAccountIds(int32_t **userIds, uint32_t *userIdsLen)
{
    (void)userIds;
    (void)userIdsLen;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnGetAccountIdByUserId(int32_t userId, int64_t *accountId, uint8_t *accountHash, uint32_t len)
{
    (void)userId;
    (void)accountId;
    (void)accountHash;
    (void)len;
    return SOFTBUS_NOT_IMPLEMENT;
}

int32_t LnnFindUserByUserIdAndUdid(const char *udid, int32_t userId, UserInfo *userInfo)
{
    (void)udid;
    (void)userId;
    (void)userInfo;
    return SOFTBUS_NOT_IMPLEMENT;
}
